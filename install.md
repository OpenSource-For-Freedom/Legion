Here is a minimal INSTALL.md file:

# Install Legion

## Requirements
- Linux (Ubuntu, Debian, Arch, Fedora)
- GCC (`sudo apt install build-essential` on Debian-based systems)
- `make` (`sudo apt install make`)

## Installation
Clone the repository:
```sh
git clone https://github.com/yourusername/legion.git
cd legion
```
## Compile the program:

```sh
make

```
## Run the scanner:

```sh
./legion /path/to/scan

```
## Install globally:

```sh
sudo cp legion /usr/local/bin/

```
## To remove Legion:

```sh
sudo rm /usr/local/bin/legion
make clean

(Contact for any needed modifications)