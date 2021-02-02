
Debian
====================
This directory contains files used to package axivd/axiv-qt
for Debian-based Linux systems. If you compile axivd/axiv-qt yourself, there are some useful files here.

## axiv: URI support ##


axiv-qt.desktop  (Gnome / Open Desktop)
To install:

	sudo desktop-file-install axiv-qt.desktop
	sudo update-desktop-database

If you build yourself, you will either need to modify the paths in
the .desktop file or copy or symlink your axivqt binary to `/usr/bin`
and the `../../share/pixmaps/axiv128.png` to `/usr/share/pixmaps`

axiv-qt.protocol (KDE)

