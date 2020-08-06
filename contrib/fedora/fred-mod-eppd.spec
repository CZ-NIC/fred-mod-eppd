Name:           %{project_name}
Version:        %{our_version}
Release:        %{?our_release}%{!?our_release:1}%{?dist}
Summary:        FRED - server for EPP over TCP/SSL as apache module
Group:          Applications/Utils
License:        GPLv3+
URL:            http://fred.nic.cz
Source0:        %{name}-%{version}.tar.gz
Source1:        idl-%{idl_branch}.tar.gz
BuildRoot:	%{_tmppath}/%{name}-%{version}-%{release}-root-%(%{__id_u} -n)
BuildRequires:  git, gcc, apr-devel, httpd-devel, libxml2-devel, openssl-devel, ORBit2-devel, doxygen, perl, graphviz
%if 0%{?el7}
BuildRequires: centos-release-scl, llvm-toolset-7-cmake, llvm-toolset-7-build
%else
BuildRequires: cmake
%endif
Requires: httpd, libxml2, openssl, fred-mod-corba, mod_ssl, /usr/sbin/semanage, /usr/sbin/sestatus

%description
FRED (Free Registry for Enum and Domain) is free registry system for 
managing domain registrations. This package contains apache module that
implements server for EPP communication over TCP/SSL. For real work this
module communicate with fred-server via CORBA technology as provided by
mod_corba apache module

%prep
%setup -b 1

%build
%if 0%{?el7}
%{?scl:scl enable llvm-toolset-7 - << \EOF}
%global __cmake /opt/rh/llvm-toolset-7/root/usr/bin/cmake
%endif
%cmake -DCMAKE_INSTALL_PREFIX=/ -DVERSION=%{version} -DREVISION=%{our_revision} -DIDL_PROJECT_DIR=%{_topdir}/BUILD/idl-%{idl_branch} .
%make_build
%if 0%{?el7}
%{?scl:EOF}
%endif

%install
rm -rf ${RPM_BUILD_ROOT}
%make_install
find ${RPM_BUILD_ROOT}/usr/share/doc/ | cut -c$(echo -n "${RPM_BUILD_ROOT} " | wc -c)- > INSTALLED_FILES

%post
test -f /etc/httpd/conf.d/02-fred-mod-eppd-apache.conf || ln -s /usr/share/fred-mod-eppd/02-fred-mod-eppd-apache.conf /etc/httpd/conf.d/
/usr/sbin/sestatus | grep -q "SELinux status:.*disabled" || {
   /usr/sbin/semanage port -a -t http_port_t -p tcp 700
}
%preun
test ! -f /etc/httpd/conf.d/02-fred-mod-eppd-apache.conf || rm /etc/httpd/conf.d/02-fred-mod-eppd-apache.conf

%clean
rm -rf ${RPM_BUILD_ROOT}

%files -f INSTALLED_FILES
%defattr(-,root,root,-)
%{_libdir}/httpd/modules/mod_eppd.so
/usr/share/fred-mod-eppd/02-fred-mod-eppd-apache.conf
/usr/share/fred-mod-eppd/schemas/*.xsd
/usr/share/fred-mod-eppd/schemas/README
/usr/share/fred-mod-eppd/schemas/ChangeLog
/usr/share/fred-mod-eppd/ssl/README
/usr/share/fred-mod-eppd/ssl/test-cert.pem
/usr/share/fred-mod-eppd/ssl/test-key.pem

%changelog
* Sat Jan 12 2008 Jaromir Talir <jaromir.talir@nic.cz>
- initial spec file

