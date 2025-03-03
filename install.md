readme_content = """\
```
██▓    ▓█████   ▄████  ██▓ ▒█████   ███▄    █ 
▓██▒    ▓█   ▀  ██▒ ▀█▒▓██▒▒██▒  ██▒ ██ ▀█   █ 
▒██░    ▒███   ▒██░▄▄▄░▒██▒▒██░  ██▒▓██  ▀█ ██▒
▒██░    ▒▓█  ▄ ░▓█  ██▓░██░▒██   ██░▓██▒  ▐▌██▒
░██████▒░▒████▒░▒▓███▀▒░██░░ ████▓▒░▒██░   ▓██░
░ ▒░▓  ░░░ ▒░ ░ ░▒   ▒ ░▓  ░ ▒░▒░▒░ ░ ▒░   ▒ ▒ 
░ ░ ▒  ░ ░ ░  ░  ░   ░  ▒ ░  ░ ▒ ▒░ ░ ░░   ░ ▒░
  ░ ░      ░   ░ ░   ░  ▒ ░░ ░ ░ ▒     ░   ░ ░ 
    ░  ░   ░  ░      ░  ░      ░ ░           ░ 
                                               
                                                    
                                                        
```
                                                        


# Install Legion

## Requirements

Legion requires a **Linux system** and the following dependencies:

## Supported Linux Distributions

- **Ubuntu**
- **Debian**
- **Arch**
- **Fedora**

## Install GCC

To install **GCC**, run:

```sh
sudo apt install build-essential  # For Debian only
```

## Install Make

To install **Make**, run:

```sh
sudo apt install make  # For Debian only 
```

## Installation

## Clone the Repository

To **download the repository**, run:

```sh
git clone https://github.com/opensource-for-freedom/legion.git
cd legion
```

## Compile the Program

Post **cloning the repository**, srarr the file by running:

```sh
make
```
## Place file path for txt

Be sure to uodate the main file with your file path for signature based detection, and whitelisted reseources. 

## Run the Scanner

Once gathered, **Legion** can execute with:

```sh
./legion # then your you path to scan 
```

## Install Legion Globally

To **install Legion system-wide**, copy the binary to `/usr/local/bin/` using:

```sh
sudo cp legion /usr/local/bin/
```

When installed globally, **Legion** can be run from any dir using:

```sh
legion /path
```

## Uninstall Legion

To **remove Legion from your system**, delete the installed binary with:

```sh
sudo rm /usr/local/bin/legion
```

## Clean Up Compiled Files

To **clean up compiled files** from the repo, run:

```sh
make clean
```
"""
