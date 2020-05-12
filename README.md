# Converter for [`nm-settings-ifcfg-rh`-Files](https://developer.gnome.org/NetworkManager/stable/nm-settings-ifcfg-rh.html) to [`nm-settings-keyfile`-Files](https://developer.gnome.org/NetworkManager/stable/nm-settings-keyfile.html)

During my migration from Fedora to Arch-Linux I realized, that RedHat-Distros use a different file
format for NetworkManager connections ([`nm-settings-ifcfg-rh`](https://developer.gnome.org/NetworkManager/stable/nm-settings-ifcfg-rh.html)).
The default connection file format is [`nm-settings-keyfile`](https://developer.gnome.org/NetworkManager/stable/nm-settings-keyfile.html).
As I found no easy way to migrate one file format into another, I wrote this script.
It may be possible (and this would certainly be the most recommendable way)
to install `nm-settings-ifcfg` and import the old scripts.
But the required package is not available for Arch Linux.

## Usage

1. Convert your files using this script (`--help` is available)
    - There should be some helpful logging messages, that most probably tell you, that the script
        fails, because some functionality is not yet implemented.
        Open an issue if you need further properties and attach your ifcfg-file.
2. Move them to `/etc/NetworkManager/system-connections/`
3. `chown root:root /etc/NetworkManager/system-connections/*`
4. `chmod u=rw,g=o= /etc/NetworkManager/system-connections/*`
5. `nmcli connection reload`
6. Watch journal for warnings and error messages
    - If there are any warnings feel free to open an issue and attach your ifcfg-file.

## License

(c) 2020 sedrubal - [MIT](https://choosealicense.com/licenses/mit/)
