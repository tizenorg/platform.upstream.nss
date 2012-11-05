%global nss_softokn_fips_version 3.12.4

Name:           nss
Version:        3.13.6
Release:        0
License:        MPL-1.1 or GPL-2.0+ or LGPL-2.1+
Summary:        Network Security Services
Url:            http://www.mozilla.org/projects/security/pki/nss/
Group:          System/Libraries
# cvs -d :pserver:anonymous@cvs-mirror.mozilla.org:/cvsroot co -r <RTM_TAG> NSS
Source:         nss-%{version}.tar.bz2
Source1:        nss.pc.in
Source3:        nss-config.in
Source4:        %{name}-rpmlintrc
Source5:        baselibs.conf
Source6:        setup-nsssysinit.sh
Source7:        cert9.db
Source8:        key4.db
Source9:        pkcs11.txt
Patch1:         nss-opt.patch
Patch2:         system-nspr.patch
Patch3:         char.patch
Patch4:         nss-no-rpath.patch
Patch5:         renegotiate-transitional.patch
Patch6:         malloc.patch
BuildRequires:  gcc-c++
BuildRequires:  nspr-devel
BuildRequires:  pkg-config
BuildRequires:  sqlite3-devel
BuildRequires:  zlib-devel
Requires:       nss-certs
BuildRoot:      %{_tmppath}/%{name}-%{version}-build
%define nspr_ver %(rpm -q --queryformat '%{VERSION}' nspr)
Requires(pre):  nspr >= %nspr_ver
Requires(pre):  libfreebl3 >= %{nss_softokn_fips_version}
Requires(pre):  libsoftokn3 >= %{nss_softokn_fips_version}
%define nssdbdir %{_sysconfdir}/pki/nssdb
%define run_testsuite 0

%description
Network Security Services (NSS) is a set of libraries designed to
support cross-platform development of security-enabled server
applications. Applications built with NSS can support SSL v2 and v3,
TLS, PKCS #5, PKCS #7, PKCS #11, PKCS #12, S/MIME, X.509 v3
certificates, and other security standards.

%package devel
Summary:        Network (Netscape) Security Services development files
Group:          Development/Libraries/Other
Requires:       libfreebl3
Requires:       libsoftokn3
Requires:       nspr-devel
Requires:       nss = %{version}

%description devel
Network Security Services (NSS) is a set of libraries designed to
support cross-platform development of security-enabled server
applications. Applications built with NSS can support SSL v2 and v3,
TLS, PKCS #5, PKCS #7, PKCS #11, PKCS #12, S/MIME, X.509 v3
certificates, and other security standards.

%package tools
Summary:        Tools for developing, debugging, and managing applications that use NSS
Group:          System/Management
Requires(pre):  nss >= %{version}

%description tools
The NSS Security Tools allow developers to test, debug, and manage
applications that use NSS.

%package sysinit
Summary:        System NSS Initialization
Group:          System/Management
Requires:       nss >= %{version}
Requires(post): coreutils

%description sysinit
Default Operation System module that manages applications loading
NSS globally on the system. This module loads the system defined
PKCS #11 modules for NSS and chains with other NSS modules to load
any system or user configured modules.

%package -n libfreebl3
Summary:        Freebl library for the Network Security Services
Group:          System/Libraries

%description -n libfreebl3
Network Security Services (NSS) is a set of libraries designed to
support cross-platform development of security-enabled server
applications. Applications built with NSS can support SSL v2 and v3,
TLS, PKCS #5, PKCS #7, PKCS #11, PKCS #12, S/MIME, X.509 v3
certificates, and other security standards.

This package installs the freebl library from NSS.

%package -n libsoftokn3
Summary:        Network Security Services Softoken Module
Group:          System/Libraries
Requires:       libfreebl3 = %{version}

%description -n libsoftokn3
Network Security Services (NSS) is a set of libraries designed to
support cross-platform development of security-enabled server
applications. Applications built with NSS can support SSL v2 and v3,
TLS, PKCS #5, PKCS #7, PKCS #11, PKCS #12, S/MIME, X.509 v3
certificates, and other security standards.

Network Security Services Softoken Cryptographic Module

%package certs
Summary:        CA certificates for NSS
Group:          Productivity/Networking/Security

%description certs
This package contains the integrated CA root certificates from the
Mozilla project.

%prep
%setup -n nss-%{version} -q
cd mozilla
%patch1
%patch2
%patch3
%patch4
%patch5
%patch6

%build
modified="$(sed -n '/^----/n;s/ - .*$//;p;q' "%{_sourcedir}/%{name}.changes")"
DATE="\"$(date -d "${modified}" "+%%b %%e %%Y")\""
TIME="\"$(date -d "${modified}" "+%%R")\""
find . -name '*.[ch]' -print -exec sed -i "s/__DATE__/${DATE}/g;s/__TIME__/${TIME}/g" {} +

cd mozilla/security/nss
export FREEBL_NO_DEPEND=1
export NSPR_INCLUDE_DIR=`nspr-config --includedir`
export NSPR_LIB_DIR=`nspr-config --libdir`
export OPT_FLAGS="%{optflags} -fno-strict-aliasing"
export LIBDIR=%{_libdir}
%ifarch x86_64 s390x ppc64 ia64
export USE_64=1
%endif
export NSS_USE_SYSTEM_SQLITE=1
MAKE_FLAGS="BUILD_OPT=1 NSS_ENABLE_ECC=1"
make nss_build_all $MAKE_FLAGS
# run testsuite
%if 0%{?run_testsuite}
export BUILD_OPT=1
export HOST="localhost"
export DOMSUF=" "
export USE_IP=TRUE
export IP_ADDRESS="127.0.0.1"
cd tests
./all.sh
if grep "FAILED" ../../../tests_results/security/localhost.1/output.log ; then
  echo "Testsuite FAILED"
  exit 1
fi
%endif

%install
mkdir -p %{buildroot}%{_libdir}
mkdir -p %{buildroot}%{_libexecdir}/nss
mkdir -p %{buildroot}%{_includedir}/nss3
mkdir -p %{buildroot}%{_bindir}
mkdir -p %{buildroot}%{_sbindir}
mkdir -p %{buildroot}/%{_lib}
mkdir -p %{buildroot}%{nssdbdir}
pushd mozilla/dist/Linux*
# copy headers
cp -rL ../public/nss/*.h %{buildroot}%{_includedir}/nss3
# copy dynamic libs
cp -L  lib/libnss3.so \
       lib/libnssdbm3.so \
       lib/libnssdbm3.chk \
       lib/libnssutil3.so \
       lib/libnssckbi.so \
       lib/libnsssysinit.so \
       lib/libsmime3.so \
       lib/libsoftokn3.so \
       lib/libsoftokn3.chk \
       lib/libssl3.so \
       %{buildroot}%{_libdir}
cp -L  lib/libfreebl3.so \
       lib/libfreebl3.chk \
       %{buildroot}/%{_lib}
# copy static libs
cp -L  lib/libcrmf.a \
       lib/libnssb.a \
       lib/libnssckfw.a \
       %{buildroot}%{_libdir}
# copy tools
cp -L  bin/certutil \
       bin/cmsutil \
       bin/crlutil \
       bin/modutil \
       bin/pk12util \
       bin/signtool \
       bin/signver \
       bin/ssltap \
       %{buildroot}%{_bindir}
# copy unsupported tools
cp -L  bin/atob \
       bin/btoa \
       bin/derdump \
       bin/ocspclnt \
       bin/pp \
       bin/selfserv \
       bin/shlibsign \
       bin/strsclnt \
       bin/symkeyutil \
       bin/tstclnt \
       bin/vfyserv \
       bin/vfychain \
       %{buildroot}%{_libexecdir}/nss
# prepare pkgconfig file
mkdir -p %{buildroot}%{_libdir}/pkgconfig/
sed "s:%%LIBDIR%%:%{_libdir}:g
s:%%VERSION%%:%{version}:g
s:%%NSPR_VERSION%%:%{nspr_ver}:g" \
  %{SOURCE1} > %{buildroot}%{_libdir}/pkgconfig/nss.pc
# prepare nss-config file
popd
NSS_VMAJOR=`cat mozilla/security/nss/lib/nss/nss.h | grep "#define.*NSS_VMAJOR" | awk '{print $3}'`
NSS_VMINOR=`cat mozilla/security/nss/lib/nss/nss.h | grep "#define.*NSS_VMINOR" | awk '{print $3}'`
NSS_VPATCH=`cat mozilla/security/nss/lib/nss/nss.h | grep "#define.*NSS_VPATCH" | awk '{print $3}'`
cat %{SOURCE3} | sed -e "s,@libdir@,%{_libdir},g" \
                     -e "s,@prefix@,%{_prefix},g" \
                     -e "s,@exec_prefix@,%{_prefix},g" \
                     -e "s,@includedir@,%{_includedir}/nss3,g" \
                     -e "s,@MOD_MAJOR_VERSION@,$NSS_VMAJOR,g" \
                     -e "s,@MOD_MINOR_VERSION@,$NSS_VMINOR,g" \
                     -e "s,@MOD_PATCH_VERSION@,$NSS_VPATCH,g" \
                     > %{buildroot}/%{_bindir}/nss-config
chmod 755 %{buildroot}/%{_bindir}/nss-config
# setup-nsssysinfo.sh
install -m 744 %{SOURCE6} %{buildroot}%{_sbindir}/
# create empty NSS database
#LD_LIBRARY_PATH=%{buildroot}/%{_lib}:%{buildroot}%{_libdir} %{buildroot}%{_bindir}/modutil -force -dbdir "sql:%{buildroot}%{nssdbdir}" -create
#LD_LIBRARY_PATH=%{buildroot}/%{_lib}:%{buildroot}%{_libdir} %{buildroot}%{_bindir}/certutil -N -d "sql:%{buildroot}%{nssdbdir}" -f /dev/null 2>&1 > /dev/null
#chmod 644 "%{buildroot}%{nssdbdir}"/*
#sed "s:%{buildroot}::g
#s/^library=$/library=libnsssysinit.so/
#/^NSS/s/\(Flags=internal\)\(,[^m]\)/\1,moduleDBOnly\2/" \
#  %{buildroot}%{nssdbdir}/pkcs11.txt > %{buildroot}%{nssdbdir}/pkcs11.txt.sed
#  mv %{buildroot}%{nssdbdir}/pkcs11.txt{.sed,}
# copy empty NSS database
install -m 644 %{SOURCE7} %{buildroot}%{nssdbdir}
install -m 644 %{SOURCE8} %{buildroot}%{nssdbdir}
install -m 644 %{SOURCE9} %{buildroot}%{nssdbdir}
# create shlib sigs after extracting debuginfo
%define __spec_install_post \
  %{?__debug_package:%{__debug_install_post}} \
  %{__arch_install_post} \
  %{__os_install_post} \
  LD_LIBRARY_PATH=%{buildroot}/%{_lib}:%{buildroot}%{_libdir} %{buildroot}%{_libexecdir}/nss/shlibsign -i %{buildroot}%{_libdir}/libsoftokn3.so \
  LD_LIBRARY_PATH=%{buildroot}/%{_lib}:%{buildroot}%{_libdir} %{buildroot}%{_libexecdir}/nss/shlibsign -i %{buildroot}%{_libdir}/libnssdbm3.so \
  LD_LIBRARY_PATH=%{buildroot}/%{_lib}:%{buildroot}%{_libdir} %{buildroot}%{_libexecdir}/nss/shlibsign -i %{buildroot}/%{_lib}/libfreebl3.so \
%{nil}

%post -p /sbin/ldconfig

%postun -p /sbin/ldconfig

%post -n libfreebl3 -p /sbin/ldconfig

%postun -n libfreebl3 -p /sbin/ldconfig

%post -n libsoftokn3 -p /sbin/ldconfig

%postun -n libsoftokn3 -p /sbin/ldconfig

%post sysinit
/sbin/ldconfig
# make sure the current config is enabled
%{_sbindir}/setup-nsssysinit.sh on

%preun sysinit
if [ $1 = 0 ]; then
  %{_sbindir}/setup-nsssysinit.sh off
fi

%postun sysinit -p /sbin/ldconfig

%files
%defattr(-, root, root)
%{_libdir}/libnss3.so
%{_libdir}/libnssutil3.so
%{_libdir}/libsmime3.so
%{_libdir}/libssl3.so

%files devel
%defattr(644, root, root, 755)
%{_includedir}/nss3/
%{_libdir}/*.a
%{_libdir}/pkgconfig/*
%attr(755,root,root) %{_bindir}/nss-config

%files tools
%defattr(-, root, root)
%{_bindir}/*
%exclude %{_sbindir}/setup-nsssysinit.sh
%{_libexecdir}/nss/
%exclude %{_bindir}/nss-config

%files sysinit
%defattr(-, root, root)
%dir %{_sysconfdir}/pki
%dir %{_sysconfdir}/pki/nssdb
%config(noreplace) %{_sysconfdir}/pki/nssdb/*
%{_libdir}/libnsssysinit.so
%{_sbindir}/setup-nsssysinit.sh

%files -n libfreebl3
%defattr(-, root, root)
/%{_lib}/libfreebl3.so
/%{_lib}/libfreebl3.chk

%files -n libsoftokn3
%defattr(-, root, root)
%{_libdir}/libsoftokn3.so
%{_libdir}/libsoftokn3.chk
%{_libdir}/libnssdbm3.so
%{_libdir}/libnssdbm3.chk

%files certs
%defattr(-, root, root)
%{_libdir}/libnssckbi.so

%changelog
