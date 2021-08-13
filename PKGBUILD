# Maintainer: oXis <oxis44@protonmail.com>
# Original Author: https://github.com/rofl0r and https://github.com/haad

_pkgname=proxychains-ng
pkgname=$_pkgname-git
pkgver=4.16
pkgrel=1
pkgdesc="A hook preloader that allows to redirect TCP traffic of existing dynamically linked programs through one or more SOCKS or HTTP proxies"
arch=('x86_64')
url="https://github.com/oxis/proxychains-ng"
license=('GPL')
provides=('proxychains' 'proxychains-ng')
replaces=('proxychains')
conflicts=('proxychains')
depends=('glibc')
backup=('etc/proxychains.conf')
source=("git+https://github.com/oxis/$_pkgname.git")
sha512sums=('SKIP')

pkgver() {
  cd $_pkgname
  git describe --long --tags | sed 's/^v//;s/\([^-]*-g\)/r\1/;s/-/./g'
}


build() {
  cd $_pkgname
  ./configure --prefix=/usr --sysconfdir=/etc
  make
}

package() {
  cd $_pkgname
  make DESTDIR="$pkgdir/" install
  make DESTDIR="$pkgdir/" install-config
  ln -s proxychains4 "$pkgdir/usr/bin/proxychains"
}

# vim:set ts=2 sw=2 et:
 

