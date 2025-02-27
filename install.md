
# Install Legion

## Requirements

Legion requires a Linux system and the following dependencies:

- A supported Linux distribution, such as Ubuntu, Debian, Arch, or Fedora.
- GCC, which can be installed with the following command:
  
  ```sh
  sudo apt install build-essential  # For Debian-based systems

### Make, which can be installed with the following command:

> sudo apt install make  # For Debian-based systems

# Installation

## Clone the Repository

### To download Legion, use the following command:
```sh 
git clone https://github.com/YOURUSERACCOUNT/legion.git
cd legion
```sh 
## Compile the Program

### After cloning the repository, compile the program by running:

> make

## Run the Scanner

### Once compiled, Legion can be executed with the following command:

> ./legion /path/to/scan

## Install Legion Globally

### To install Legion system-wide, copy the binary to /usr/local/bin/ using:

> sudo cp legion /usr/local/bin/

### Once installed globally, Legion can be run from any directory using:

> legion /path

### Uninstall Legion

## To remove Legion from your system, delete the installed binary with:

> sudo rm /usr/local/bin/legion

### To clean up compiled files from the repository, run:

> make clean

