
Debian
====================
This directory contains files used to package aureusxivd/aureusxiv-qt
for Debian-based Linux systems. If you compile aureusxivd/aureusxiv-qt yourself, there are some useful files here.

## aureusxiv: URI support ##


aureusxiv-qt.desktop  (Gnome / Open Desktop)
To install:

	sudo desktop-file-install aureusxiv-qt.desktop
	sudo update-desktop-database

If you build yourself, you will either need to modify the paths in
the .desktop file or copy or symlink your aureusxivqt binary to `/usr/bin`
and the `../../share/pixmaps/aureusxiv128.png` to `/usr/share/pixmaps`

aureusxiv-qt.protocol (KDE)

