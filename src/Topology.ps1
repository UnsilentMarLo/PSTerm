<#
.SYNOPSIS
    Turn neighbour lists (CDP / LLDP) into a picture of the network: a graph of devices
    and the links between them, as SVG, PNG or a plain list.

.DESCRIPTION
    Input is what the cdp-topology plugin returns: one row per neighbour as seen from one
    device. A link reported from both ends, or by both CDP and LLDP, is one link here.
#>

Set-StrictMode -Version Latest

function Get-PSTermTopology {
    <#
    .SYNOPSIS
        Rows of "this device sees that neighbour on this port" -> Nodes and Links.
    .PARAMETER Row
        Objects with Device, LocalPort, RemoteDevice, RemotePort and optionally Protocol,
        RemoteIp and Platform.
    #>
    [CmdletBinding()]
    param([Parameter(Mandatory)][AllowEmptyCollection()][object[]]$Row)

    $nodes = [ordered]@{}
    $links = [ordered]@{}

    $node = {
        param([string]$name)
        if (-not $nodes.Contains($name)) { $nodes[$name] = [ordered]@{ Name = $name; Ip = ''; Platform = ''; Seed = $false } }
        $nodes[$name]
    }

    foreach ($r in $Row) {
        $a = Get-PSTermShortName ([string]$r.Device)
        $b = Get-PSTermShortName ([string]$r.RemoteDevice)
        if (-not $a -or -not $b) { continue }
        $pa = Get-PSTermShortPort ([string]$r.LocalPort)
        $pb = Get-PSTermShortPort ([string]$r.RemotePort)

        $na = & $node $a; $na.Seed = $true
        $nb = & $node $b
        if ($r.PSObject.Properties['RemoteIp'] -and $r.RemoteIp -and -not $nb.Ip) { $nb.Ip = [string]$r.RemoteIp }
        if ($r.PSObject.Properties['Platform'] -and $r.Platform -and -not $nb.Platform) { $nb.Platform = [string]$r.Platform }

        # The same cable seen from either end is one link: order its two ends.
        $endA = "$a|$pa"; $endB = "$b|$pb"
        if ([string]::CompareOrdinal($endA, $endB) -gt 0) { $t = $endA; $endA = $endB; $endB = $t; $x = $a; $a = $b; $b = $x; $y = $pa; $pa = $pb; $pb = $y }
        $key = "$endA<->$endB"
        $protocol = $(if ($r.PSObject.Properties['Protocol'] -and $r.Protocol) { [string]$r.Protocol } else { '' })
        if ($links.Contains($key)) {
            if ($protocol -and ($links[$key].Protocols -notcontains $protocol)) { $links[$key].Protocols += $protocol }
        }
        else {
            $links[$key] = [ordered]@{ A = $a; PortA = $pa; B = $b; PortB = $pb; Protocols = @($(if ($protocol) { $protocol })) }
        }
    }

    [pscustomobject]@{
        Nodes = @($nodes.Values | ForEach-Object { [pscustomobject]$_ })
        Links = @($links.Values | ForEach-Object { [pscustomobject]@{ A = $_.A; PortA = $_.PortA; B = $_.B; PortB = $_.PortB; Protocols = ($_.Protocols -join '+') } })
    }
}

function Get-PSTermTopologyLayout {
    <#
    .SYNOPSIS
        Put the devices on a grid by how far they are from the first one, and work out
        where every link is drawn. Shared by the SVG and PNG writers so they agree.
    #>
    [CmdletBinding()]
    param([Parameter(Mandatory)]$Topology)

    $w = 190; $h = 54; $hGap = 120; $vGap = 130; $margin = 50
    $nodes = @($Topology.Nodes); $links = @($Topology.Links)

    $adjacent = @{}
    foreach ($n in $nodes) { $adjacent[$n.Name] = New-Object System.Collections.Generic.List[string] }
    foreach ($l in $links) { $adjacent[$l.A].Add($l.B); $adjacent[$l.B].Add($l.A) }

    # Layers: breadth-first from the best connected seed, then from whatever is left.
    $layerOf = @{}
    $order = @($nodes | Sort-Object @{ Expression = { -[int]$_.Seed } }, @{ Expression = { -$adjacent[$_.Name].Count } }, Name)
    $nextLayerBase = 0
    foreach ($root in $order) {
        if ($layerOf.ContainsKey($root.Name)) { continue }
        $layerOf[$root.Name] = $nextLayerBase
        $queue = New-Object System.Collections.Generic.Queue[string]
        $queue.Enqueue($root.Name)
        $deepest = $nextLayerBase
        while ($queue.Count -gt 0) {
            $cur = $queue.Dequeue()
            foreach ($nb in ($adjacent[$cur] | Sort-Object -Unique)) {
                if (-not $layerOf.ContainsKey($nb)) {
                    $layerOf[$nb] = $layerOf[$cur] + 1
                    if ($layerOf[$nb] -gt $deepest) { $deepest = $layerOf[$nb] }
                    $queue.Enqueue($nb)
                }
            }
        }
        $nextLayerBase = $deepest + 1
    }

    $layers = @{}
    foreach ($n in $nodes) {
        $k = [int]$layerOf[$n.Name]
        if (-not $layers.ContainsKey($k)) { $layers[$k] = New-Object System.Collections.Generic.List[object] }
        $layers[$k].Add($n)
    }
    $layerKeys = @($layers.Keys | Sort-Object)
    $widest = 1
    foreach ($k in $layerKeys) { if ($layers[$k].Count -gt $widest) { $widest = $layers[$k].Count } }
    $canvasW = $widest * ($w + $hGap) - $hGap + 2 * $margin

    $pos = @{}
    $row = 0
    foreach ($k in $layerKeys) {
        $items = @($layers[$k] | Sort-Object Name)
        $rowW = $items.Count * ($w + $hGap) - $hGap
        $x0 = ($canvasW - $rowW) / 2
        for ($i = 0; $i -lt $items.Count; $i++) {
            $pos[$items[$i].Name] = [pscustomobject]@{
                Name = $items[$i].Name; Ip = $items[$i].Ip; Platform = $items[$i].Platform; Seed = $items[$i].Seed
                X = [int]($x0 + $i * ($w + $hGap)); Y = [int]($margin + $row * ($h + $vGap)); W = $w; H = $h
            }
        }
        $row++
    }
    $canvasH = $(if ($row -eq 0) { 2 * $margin } else { [int]($margin * 2 + $row * ($h + $vGap) - $vGap) })

    # Where a link meets a device: the ends are spread along the bottom edge (links to
    # devices below) or the top edge (links to devices above), in the order of where the
    # other end is, so lines neither converge on one point nor cross needlessly.
    $slots = @{}
    for ($i = 0; $i -lt $links.Count; $i++) {
        $a = $pos[$links[$i].A]; $b = $pos[$links[$i].B]
        if ($a.Y -eq $b.Y) { continue }
        $upper = $(if ($a.Y -lt $b.Y) { $a } else { $b }); $lower = $(if ($a.Y -lt $b.Y) { $b } else { $a })
        foreach ($s in @(@("$($upper.Name)|bottom", $i, $lower.X), @("$($lower.Name)|top", $i, $upper.X))) {
            if (-not $slots.ContainsKey($s[0])) { $slots[$s[0]] = New-Object System.Collections.Generic.List[object] }
            $slots[$s[0]].Add($s)
        }
    }
    $slotX = @{}
    foreach ($key in $slots.Keys) {
        $name = $key.Substring(0, $key.LastIndexOf('|'))
        $items = @($slots[$key] | Sort-Object @{ Expression = { $_[2] } }, @{ Expression = { $_[1] } })
        for ($k = 0; $k -lt $items.Count; $k++) { $slotX["$($items[$k][1])|$name"] = $pos[$name].X + $w * ($k + 1) / ($items.Count + 1) }
    }

    $pairCount = @{}; $drawn = @()
    for ($i = 0; $i -lt $links.Count; $i++) {
        $l = $links[$i]
        $a = $pos[$l.A]; $b = $pos[$l.B]
        if ($a.Y -eq $b.Y) {
            # Side by side: a straight line, parallel ones stacked.
            $pk = (@($l.A, $l.B) | Sort-Object) -join '|'
            $idx = $(if ($pairCount.ContainsKey($pk)) { $pairCount[$pk] } else { 0 })
            $pairCount[$pk] = $idx + 1
            $left = $(if ($a.X -le $b.X) { $a } else { $b }); $right = $(if ($a.X -le $b.X) { $b } else { $a })
            $y = $left.Y + $h / 2 + 14 * $idx - 7
            $p1 = @(($left.X + $w), $y); $p2 = @($right.X, $y)
            $first = $(if ($left.Name -eq $l.A) { $p1 } else { $p2 }); $second = $(if ($left.Name -eq $l.A) { $p2 } else { $p1 })
        }
        else {
            $aUpper = ($a.Y -lt $b.Y)
            $ax = $slotX["$i|$($l.A)"]; $bx = $slotX["$i|$($l.B)"]
            $first = @($ax, $(if ($aUpper) { $a.Y + $h } else { $a.Y }))
            $second = @($bx, $(if ($aUpper) { $b.Y } else { $b.Y + $h }))
        }
        $drawn += [pscustomobject]@{ A = $l.A; PortA = $l.PortA; B = $l.B; PortB = $l.PortB; Protocols = $l.Protocols; SameRow = ($a.Y -eq $b.Y); X1 = [int]$first[0]; Y1 = [int]$first[1]; X2 = [int]$second[0]; Y2 = [int]$second[1] }
    }
    [pscustomobject]@{ Width = [int]$canvasW; Height = [int]$canvasH; Nodes = @($pos.Values | Sort-Object Y, X); Links = $drawn }
}

function Get-PSTermLinkLabelPoint {
    <#
    .SYNOPSIS
        Where the two port names of a link are written: near each end, above the line when
        the devices are side by side (the line is short there) and on the line otherwise.
    #>
    param([Parameter(Mandatory)]$Link)
    $fa = $(if ($Link.SameRow) { 0.25 } else { 0.2 }); $fb = 1 - $fa
    $lift = $(if ($Link.SameRow) { -9 } else { 0 })
    @(
        [pscustomobject]@{ Text = [string]$Link.PortA; X = ($Link.X1 + ($Link.X2 - $Link.X1) * $fa); Y = ($Link.Y1 + ($Link.Y2 - $Link.Y1) * $fa + $lift) }
        [pscustomobject]@{ Text = [string]$Link.PortB; X = ($Link.X1 + ($Link.X2 - $Link.X1) * $fb); Y = ($Link.Y1 + ($Link.Y2 - $Link.Y1) * $fb + $lift) }
    )
}

function ConvertTo-PSTermTopologySvg {
    <#
    .SYNOPSIS
        The topology as an SVG document (a string).
    #>
    [CmdletBinding()]
    param([Parameter(Mandatory)]$Topology, [string]$Title = 'Network topology')

    $layout = Get-PSTermTopologyLayout -Topology $Topology
    $esc = { param($s) [System.Security.SecurityElement]::Escape([string]$s) }
    $inv = [System.Globalization.CultureInfo]::InvariantCulture

    $sb = New-Object System.Text.StringBuilder
    [void]$sb.AppendLine('<?xml version="1.0" encoding="UTF-8"?>')
    [void]$sb.AppendLine(('<svg xmlns="http://www.w3.org/2000/svg" width="{0}" height="{1}" viewBox="0 0 {0} {1}" font-family="Segoe UI, Arial, sans-serif">' -f $layout.Width, $layout.Height))
    [void]$sb.AppendLine("<title>$(& $esc $Title)</title>")
    [void]$sb.AppendLine('<rect width="100%" height="100%" fill="#ffffff"/>')

    foreach ($l in $layout.Links) {
        [void]$sb.AppendLine(('<line x1="{0}" y1="{1}" x2="{2}" y2="{3}" stroke="#6b7a90" stroke-width="2"><title>{4}:{5} - {6}:{7}</title></line>' -f $l.X1, $l.Y1, $l.X2, $l.Y2, (& $esc $l.A), (& $esc $l.PortA), (& $esc $l.B), (& $esc $l.PortB)))
    }
    foreach ($l in $layout.Links) {
        foreach ($pt in (Get-PSTermLinkLabelPoint -Link $l)) {
            if (-not $pt.Text) { continue }
            [void]$sb.AppendLine(('<text x="{0}" y="{1}" font-size="11" text-anchor="middle" fill="#2b3544" stroke="#ffffff" stroke-width="4" paint-order="stroke">{2}</text>' -f ([string]::Format($inv, '{0:0.#}', $pt.X)), ([string]::Format($inv, '{0:0.#}', $pt.Y)), (& $esc $pt.Text)))
        }
    }
    foreach ($n in $layout.Nodes) {
        $stroke = $(if ($n.Seed) { '#2f6fd0' } else { '#8a96a8' })
        $fill = $(if ($n.Seed) { '#e8f0fc' } else { '#f3f5f8' })
        [void]$sb.AppendLine(('<rect x="{0}" y="{1}" width="{2}" height="{3}" rx="8" fill="{4}" stroke="{5}" stroke-width="2"/>' -f $n.X, $n.Y, $n.W, $n.H, $fill, $stroke))
        [void]$sb.AppendLine(('<text x="{0}" y="{1}" font-size="14" font-weight="600" text-anchor="middle" fill="#1a2330">{2}</text>' -f ($n.X + $n.W / 2), ($n.Y + 23), (& $esc $n.Name)))
        $sub = (@($n.Platform, $n.Ip) | Where-Object { $_ }) -join '  '
        if ($sub) { [void]$sb.AppendLine(('<text x="{0}" y="{1}" font-size="11" text-anchor="middle" fill="#5a6678">{2}</text>' -f ($n.X + $n.W / 2), ($n.Y + 41), (& $esc $sub))) }
    }
    [void]$sb.AppendLine('</svg>')
    $sb.ToString()
}

function New-PSTermTopologyBitmap {
    <#
    .SYNOPSIS
        The topology drawn into a bitmap (the caller disposes it). Used for the preview in
        the plugin window and for the PNG file.
    #>
    [CmdletBinding()]
    param(
        [Parameter(Mandatory)]$Topology,
        [double]$Scale = 1.5,
        # Colours for the page; the default is the white page used for saved files.
        [System.Drawing.Color]$Background = [System.Drawing.Color]::White
    )

    Add-Type -AssemblyName System.Drawing
    $layout = Get-PSTermTopologyLayout -Topology $Topology
    $dark = $Background.GetBrightness() -lt 0.5
    $c = @{
        Line = $(if ($dark) { '#8a96a8' } else { '#6b7a90' }); Text = $(if ($dark) { '#e4e7ee' } else { '#1a2330' }); Muted = $(if ($dark) { '#9aa3b2' } else { '#5a6678' })
        SeedFill = $(if ($dark) { '#26364f' } else { '#e8f0fc' }); SeedEdge = '#2f6fd0'; Fill = $(if ($dark) { '#2b2f3a' } else { '#f3f5f8' }); Edge = '#8a96a8'
    }
    $html = { param($h) [System.Drawing.ColorTranslator]::FromHtml($h) }

    $bmp = New-Object System.Drawing.Bitmap([int]($layout.Width * $Scale), [int]($layout.Height * $Scale))
    $g = [System.Drawing.Graphics]::FromImage($bmp)
    try {
        $g.SmoothingMode = 'AntiAlias'
        $g.TextRenderingHint = 'AntiAliasGridFit'
        $g.ScaleTransform([single]$Scale, [single]$Scale)
        $g.Clear($Background)

        $line = New-Object System.Drawing.Pen((& $html $c.Line), 2)
        $small = New-Object System.Drawing.Font('Segoe UI', 8.5)
        $name = New-Object System.Drawing.Font('Segoe UI', 10.5, [System.Drawing.FontStyle]::Bold)
        $text = New-Object System.Drawing.SolidBrush((& $html $c.Text))
        $muted = New-Object System.Drawing.SolidBrush((& $html $c.Muted))
        $page = New-Object System.Drawing.SolidBrush($Background)
        $center = New-Object System.Drawing.StringFormat; $center.Alignment = 'Center'; $center.LineAlignment = 'Center'

        foreach ($l in $layout.Links) { $g.DrawLine($line, $l.X1, $l.Y1, $l.X2, $l.Y2) }
        foreach ($l in $layout.Links) {
            foreach ($pt in (Get-PSTermLinkLabelPoint -Link $l)) {
                if (-not $pt.Text) { continue }
                $tx = [single]$pt.X; $ty = [single]$pt.Y
                $size = $g.MeasureString($pt.Text, $small)
                $g.FillRectangle($page, ($tx - $size.Width / 2), ($ty - $size.Height / 2), $size.Width, $size.Height)
                $g.DrawString($pt.Text, $small, $text, $tx, $ty, $center)
            }
        }
        foreach ($n in $layout.Nodes) {
            $rect = New-Object System.Drawing.Rectangle($n.X, $n.Y, $n.W, $n.H)
            $fill = New-Object System.Drawing.SolidBrush((& $html $(if ($n.Seed) { $c.SeedFill } else { $c.Fill })))
            $edge = New-Object System.Drawing.Pen((& $html $(if ($n.Seed) { $c.SeedEdge } else { $c.Edge })), 2)
            $g.FillRectangle($fill, $rect); $g.DrawRectangle($edge, $rect)
            $g.DrawString($n.Name, $name, $text, [single]($n.X + $n.W / 2), [single]($n.Y + 19), $center)
            $sub = (@($n.Platform, $n.Ip) | Where-Object { $_ }) -join '  '
            if ($sub) { $g.DrawString($sub, $small, $muted, [single]($n.X + $n.W / 2), [single]($n.Y + 38), $center) }
            $fill.Dispose(); $edge.Dispose()
        }
        $line.Dispose(); $small.Dispose(); $name.Dispose(); $text.Dispose(); $muted.Dispose(); $page.Dispose()
    }
    catch { $bmp.Dispose(); throw }
    finally { $g.Dispose() }
    $bmp
}

function Save-PSTermTopologyPng {
    <#
    .SYNOPSIS
        The same picture as a PNG file.
    #>
    [CmdletBinding()]
    param([Parameter(Mandatory)]$Topology, [Parameter(Mandatory)][string]$Path, [double]$Scale = 1.5)

    $bmp = New-PSTermTopologyBitmap -Topology $Topology -Scale $Scale
    try {
        $dir = Split-Path -Parent $Path
        if ($dir -and -not (Test-Path -LiteralPath $dir)) { New-Item -ItemType Directory -Path $dir -Force | Out-Null }
        $bmp.Save($Path, [System.Drawing.Imaging.ImageFormat]::Png)
    }
    finally { $bmp.Dispose() }
}