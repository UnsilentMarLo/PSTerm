# PSTerm

PSTerm is a powerful, native PowerShell terminal for Serial, SSH, and Telnet connections, designed to provide a seamless and feature-rich experience directly within the PowerShell environment. It offers a graphical user interface for managing connection profiles and settings, with support for both WPF and Windows Forms for maximum compatibility.

## Features

- **Multiple Connection Types**: Connect to devices and servers using Serial (COM ports), SSH, or Telnet.
- **Profile Management**: Save and load connection settings as profiles for quick and easy access. Default profiles for each connection type are provided.
- **Customizable Terminal**: Adjust terminal colors, cursor size, and other settings to suit your preferences.
- **Session Logging**: Log session output to a file, with options for raw data logging and password obfuscation.
- **Auto-Input Scripts**: Automate repetitive tasks by sending a predefined sequence of commands upon connection.
- **Keep-Alive**: Prevent session timeouts by sending periodic keep-alive messages.
- **Dual UI Support**: Utilizes WPF for a modern user experience and falls back to Windows Forms when WPF is unavailable.

## Requirements

- **PowerShell**: PowerShell 5.1 or later.
- **.NET Framework**: .NET Framework 4.5 or later.
- **Posh-SSH Module**: The required `Posh-SSH` module is included in the `lib` directory.

## Installation

No installation is required. Simply run the `PSTerm.ps1` script from a PowerShell console.

```powershell
.\PSTerm.ps1
```

To make the application easily accessible, you can create a shortcut to `PSTerm.ps1` on your desktop or in a convenient location.

## Usage

When you run `PSTerm.ps1`, a configuration window will appear, allowing you to set up your connection.

1.  **Select a Profile**: Choose an existing profile from the dropdown list or create a new one by typing a name and clicking **Save**.
2.  **Choose Connection Type**: Select **Serial**, **SSH**, or **Telnet**.
3.  **Configure Settings**:
    -   **Serial**: Select the COM port, baud rate, and other serial settings.
    -   **SSH**: Enter the host, username, and port.
    -   **Telnet**: Enter the host and port.
4.  **Customize Terminal**: Adjust terminal colors, logging options, and other settings as needed.
5.  **Connect**: Click **Connect** to start the session.

## Compilation

A `Compile.ps1` script is provided to package the application into a single executable file. This script uses the `PS2EXE` module, which is included in the `Compile` directory.

To compile the application, run the `Compile.ps1` script from a PowerShell console:

```powershell
.\Compile.ps1
```

The compiled executable will be placed in the root directory.

## Project Structure

-   `src/`: Contains the main source code for the application.
    -   `src/PSTerm.ps1`: The main script file, containing the application logic.
    -   `src/ui.ps1`: The script file that defines the user interface for both WPF and Windows Forms.
    -   `src/lib/`: Contains the required `Posh-SSH` module.
    -   `src/ConnectionConfig.xaml`: The XAML file that defines the WPF user interface.
    -   `src/PSTerm.ps1`: The distribution copy of the main script.
-   `Compile.ps1`: The script used to compile the application into an executable.
-   `PSTerm.lnk`: A dynamic shortcut to launch the application without compiling.
-   `Compile/`: Contains the `PS2EXE` module used for compiling the application.

## Contributing

Contributions are welcome. Please open an issue to discuss any proposed changes before submitting a pull request.

## License

This project is licensed under the MIT License. See the `LICENSE` file for details.
