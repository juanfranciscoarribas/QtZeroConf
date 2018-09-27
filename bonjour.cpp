/**************************************************************************************************
---------------------------------------------------------------------------------------------------
	Copyright (C) 2015  Jonathan Bagg
	This file is part of QtZeroConf.

	QtZeroConf is free software: you can redistribute it and/or modify
	it under the terms of the GNU Lesser General Public License as published by
	the Free Software Foundation, either version 3 of the License, or
	(at your option) any later version.

	QtZeroConf is distributed in the hope that it will be useful,
	but WITHOUT ANY WARRANTY; without even the implied warranty of
	MERCHANTABILITY or FITNESS FOR A PARTICULAR PURPOSE.  See the
	GNU Lesser General Public License for more details.

	You should have received a copy of the GNU Lesser General Public License
	along with QtZeroConf.  If not, see <http://www.gnu.org/licenses/>.
---------------------------------------------------------------------------------------------------
   Project name : QtZeroConf
   File name    : bonjour.cpp
   Created      : 20 July 2015
   Author(s)    : Jonathan Bagg
---------------------------------------------------------------------------------------------------
   Wrapper for Apple's Bonjour library for use on Windows, MACs and iOS
---------------------------------------------------------------------------------------------------
**************************************************************************************************/
#include "qzeroconf.h"
#include "bonjour_p.h"

#define LOGDEBUG_STATIC	qDebug() << __FUNCTION__ << ":"
#define LOGDEBUG qDebug() << __FUNCTION__  << ":" << this << ":"

QZeroConfPrivate::QZeroConfPrivate(QZeroConf *parent)
{
	pub = parent;
	dnssRef = NULL;
	browser = NULL;
	resolver = NULL;
	addrInfo = NULL;
	bs = NULL;
	browserSocket = NULL;
	resolverSocket = NULL;
  addressSocket = NULL;
}

QZeroConfPrivate::~QZeroConfPrivate()
{
	cleanUp(dnssRef);
	cleanUp(browser);
	cleanUp(resolver);
}

void QZeroConfPrivate::bsRead()
{
  LOGDEBUG << "bsRead, calling DNSServiceProcessResult on dnsRef...";
	DNSServiceErrorType err = DNSServiceProcessResult(dnssRef);
	if (err != kDNSServiceErr_NoError) {
    LOGDEBUG << "bsRead, error on DNSServiceProcessResult!";
		cleanUp(dnssRef);
		emit pub->error(QZeroConf::serviceRegistrationFailed);
	}
}

void QZeroConfPrivate::browserRead()
{
	LOGDEBUG << "browserRead, calling DNSServiceProcessResult...";
	DNSServiceErrorType err = DNSServiceProcessResult(browser);
	if (err != kDNSServiceErr_NoError) {
    LOGDEBUG << "browserRead, error on DNSServiceProcessResult!";
		cleanUp(browser);
		emit pub->error(QZeroConf::browserFailed);
	}
}

void QZeroConfPrivate::addressRead()
{
	LOGDEBUG << "addressRead, calling DNSServiceProcessResult...";
	DNSServiceErrorType err = DNSServiceProcessResult(addrInfo);
	if (err != kDNSServiceErr_NoError)
  {
    LOGDEBUG << "addressRead, error on DNSServiceProcessResult!";
		cleanUp(addrInfo);
  }
}

void QZeroConfPrivate::resolverRead()
{
	LOGDEBUG << "resolverRead, calling DNSServiceProcessResult...";
	DNSServiceErrorType err = DNSServiceProcessResult(resolver);
	if (err != kDNSServiceErr_NoError)
  {
    LOGDEBUG << "resolverRead, error on DNSServiceProcessResult!";
		cleanUp(resolver);
  }
}

void QZeroConfPrivate::resolve(void)
{
	LOGDEBUG << "resolve, calling DNSServiceResolve: iface" << work.head().interfaceIndex() << "hostname" << work.head().name().toUtf8() << "type" << work.head().type().toUtf8() << "domain" << work.head().domain().toUtf8();
	DNSServiceErrorType err = DNSServiceResolve(&resolver, 0, work.head().interfaceIndex(), work.head().name().toUtf8(), work.head().type().toUtf8(), work.head().domain().toUtf8(), (DNSServiceResolveReply) resolverCallback, this);
	if (err == kDNSServiceErr_NoError) {
		int sockfd = DNSServiceRefSockFD(resolver);
		if (sockfd == -1) {
      LOGDEBUG << "Error in DNSServiceRefSockFD, cleaning up!...";
			cleanUp(resolver);
		}
		else {
			LOGDEBUG << "Successful DNSServiceResolve, listening on socket" << sockfd << ", resolverSocket=" << resolverSocket;
      delete resolverSocket;
			resolverSocket = new QSocketNotifier(sockfd, QSocketNotifier::Read, this);
			connect(resolverSocket, SIGNAL(activated(int)), this, SLOT(resolverRead()));
		}
	}
	else {
    LOGDEBUG << "Error in DNSServiceResolve, cleaning up!...";
		cleanUp(resolver);
	}
}

void DNSSD_API QZeroConfPrivate::registerCallback(DNSServiceRef, DNSServiceFlags, DNSServiceErrorType errorCode, const char *, const char *, const char *, void *userdata)
{
	QZeroConfPrivate *ref = static_cast<QZeroConfPrivate *>(userdata);

	if (errorCode == kDNSServiceErr_NoError) {
		emit ref->pub->servicePublished();
	}
	else {
		ref->cleanUp(ref->dnssRef);
		emit ref->pub->error(QZeroConf::serviceRegistrationFailed);
	}
}

void DNSSD_API QZeroConfPrivate::browseCallback(DNSServiceRef sdRef, DNSServiceFlags flags,
	quint32 interfaceIndex, DNSServiceErrorType err, const char *name,
	const char *type, const char *domain, void *userdata)
	{
		QString key;
		QZeroConfService zcs;
		QZeroConfPrivate *ref = static_cast<QZeroConfPrivate *>(userdata);

		LOGDEBUG_STATIC << "browseCallback";
		if (err != kDNSServiceErr_NoError) {
			ref->cleanUp(ref->browser);
			emit ref->pub->error(QZeroConf::browserFailed);
		}

		key = name + QString::number(interfaceIndex);
		if (flags & kDNSServiceFlagsAdd) {
			if (!ref->pub->services.contains(key)) {
				LOGDEBUG_STATIC << "browseCallback, brand new service (ADD):" << name << type << domain << interfaceIndex;
				zcs.setName(name);
				zcs.setType(type);
				zcs.setDomain(domain);
				zcs.setInterfaceIndex(interfaceIndex);

				if (!ref->work.size()) {
					LOGDEBUG_STATIC << "browseCallback, first item on work queue -> enqueue & resolve!";
					ref->work.enqueue(zcs);
					ref->resolve();
				}
				else {
					LOGDEBUG_STATIC << "browseCallback, more items on work queue -> enqueueing";
					ref->work.enqueue(zcs);
				}
			}
			else {
				LOGDEBUG_STATIC << "browseCallback, existing service (ADD), skipping...";
			}
		}
		else if (ref->pub->services.contains(key)) {
			LOGDEBUG_STATIC << "browseCallback, existing service (REMOVE):";
			qDebug() << key;
			zcs = ref->pub->services[key];
			ref->pub->services.remove(key);
			emit ref->pub->serviceRemoved(zcs);
		}
		else {
			LOGDEBUG_STATIC << "browseCallback, unknown service (REMOVE)?, ERROR!";
      ref->cleanUp(ref->browser);
      emit ref->pub->error(QZeroConf::browserFailed);
		}
}

void DNSSD_API QZeroConfPrivate::resolverCallback(DNSServiceRef sdRef, DNSServiceFlags,
		quint32 interfaceIndex, DNSServiceErrorType err, const char *,
		const char *hostName, quint16 port, quint16 txtLen,
		const char * txtRecord, void *userdata)
{
  QZeroConfPrivate *ref = static_cast<QZeroConfPrivate *>(userdata);

	if (err != kDNSServiceErr_NoError) {
    if (ref) {
      ref->cleanUp(ref->resolver);
    }
		LOGDEBUG_STATIC << "resolverCallback: Error! SKIPPING...";
		return;
	}

	LOGDEBUG_STATIC << "resolverCallback:" << hostName << qFromBigEndian<quint16>(port) << interfaceIndex;

	qint16 recLen;
	while (txtLen > 0)		// add txt records
	{
		recLen = txtRecord[0];
		txtRecord++;
		QByteArray avahiText((const char *)txtRecord, recLen);
		QList<QByteArray> pair = avahiText.split('=');
		if (pair.size() == 2)
			ref->work.head().appendTxt(pair.at(0), pair.at(1));
		else
			ref->work.head().appendTxt(pair.at(0));

		txtLen-= recLen + 1;
		txtRecord+= recLen;
	}

	ref->work.head().setHost(hostName);
	ref->work.head().setPort(qFromBigEndian<quint16>(port));

  ref->cleanUp(ref->resolver);

	LOGDEBUG_STATIC << "resolverCallback, calling DNSServiceGetAddrInfo";
	err = DNSServiceGetAddrInfo(&ref->addrInfo, kDNSServiceFlagsForceMulticast, interfaceIndex, ref->protocol, hostName, (DNSServiceGetAddrInfoReply) addressReply, ref);
	if (err == kDNSServiceErr_NoError) {
    LOGDEBUG_STATIC << "DNSServiceGetAddrInfo successful, waiting callback to be called...";
		int sockfd = DNSServiceRefSockFD(ref->addrInfo);
		if (sockfd != -1) {
			LOGDEBUG_STATIC << "Succesful DNSServiceGetAddrInfo, waiting on addressSocket: " << sockfd;
			delete ref->addressSocket;
			ref->addressSocket = new QSocketNotifier(sockfd, QSocketNotifier::Read, ref);
			connect(ref->addressSocket, SIGNAL(activated(int)), ref, SLOT(addressRead()));
		}
	}
  else {
    LOGDEBUG_STATIC << "Error on DNSServiceGetAddrInfo";
    ref->cleanUp(ref->addrInfo);
  }
}

void DNSSD_API QZeroConfPrivate::addressReply(DNSServiceRef sdRef,
	DNSServiceFlags flags, quint32 interfaceIndex,
	DNSServiceErrorType err, const char *hostName,
	const struct sockaddr* address, quint32 ttl, void *userdata)
	{
		Q_UNUSED(interfaceIndex);
		Q_UNUSED(sdRef);
		Q_UNUSED(ttl);
		Q_UNUSED(hostName);

		LOGDEBUG_STATIC << "addressReply:" << hostName;
		QZeroConfPrivate *ref = static_cast<QZeroConfPrivate *>(userdata);

		if (err != kDNSServiceErr_NoError) {
      ref->cleanUp(ref->addrInfo);
			return;
		}

		if (flags & kDNSServiceFlagsAdd) {
			QHostAddress hAddress(address);
			if (hAddress.protocol() == QAbstractSocket::IPv6Protocol)
			{
				ref->work.head().setIpv6(hAddress);
			}
			else
			{
				ref->work.head().setIp(hAddress);
			}

			QString key = ref->work.head().name() + QString::number(interfaceIndex);
			if (!ref->pub->services.contains(key))
			{
				ref->pub->services.insert(key, ref->work.head());
				LOGDEBUG_STATIC << "addressReply, emitting serviceAdded signal for " << hostName;
				emit ref->pub->serviceAdded(ref->work.head());
			}
			else {
				LOGDEBUG_STATIC << "addressReply, emitting serviceUpdated signal for " << hostName;
				emit ref->pub->serviceUpdated(ref->work.head());
			}
		}

		if (!(flags & kDNSServiceFlagsMoreComing)) {
			ref->cleanUp(ref->addrInfo);
		}
		else {
			LOGDEBUG_STATIC << "addressReply, kDNSServiceFlagsMoreComing! SKIPPING cleanup for resolver";
		}
}

void QZeroConfPrivate::cleanUp(DNSServiceRef toClean)
{
	if (!toClean)
		return;

	if (toClean == addrInfo) {
		LOGDEBUG << "cleanUp: addrInfo";
		addrInfo = NULL;

    if (addressSocket) {
      delete addressSocket;
      addressSocket = NULL;
    }

    // reolving next item
    if(!work.isEmpty()) {
      LOGDEBUG << "cleanUp: resolver: Dequeueing last item from work";
      work.dequeue();
    }
    if (work.size()) {
      LOGDEBUG << "cleanUp: resolver: Calling resolve to process work list's next item";
      resolve();
    }
	}
	else if (toClean == resolver) {
		LOGDEBUG << "cleanUp: resolver";
		if (resolverSocket) {
			delete resolverSocket;
			resolverSocket = NULL;
		}
		resolver = NULL;
	}
	else if (toClean == browser) {
		LOGDEBUG << "cleanUp: browser";
		browser = NULL;
		if (browserSocket) {
			delete browserSocket;
			browserSocket = NULL;
		}
		QMap<QString, QZeroConfService >::iterator i;
		LOGDEBUG << "cleanUp: browser: Removing found services...";
		for (i = pub->services.begin(); i != pub->services.end(); i++) {
			emit pub->serviceRemoved(*i);
		}
		pub->services.clear();
	}
	else if (toClean == dnssRef) {
		LOGDEBUG << "cleanUp: dnsRef";
		dnssRef = NULL;
		if (bs) {
			delete bs;
			bs = NULL;
		}
	}
	else {
		LOGDEBUG << "cleanUp: unknown clean-up, SKIPPING!";
	}

		LOGDEBUG << "cleanUp: Calling DNSServiceRefDeallocate";
		DNSServiceRefDeallocate(toClean);
}

QZeroConf::QZeroConf(QObject *parent) : QObject (parent)
{
	pri = new QZeroConfPrivate(this);
	qRegisterMetaType<QZeroConfService>("QZeroConfService");
}

QZeroConf::~QZeroConf()
{
	delete pri;
}

void QZeroConf::startServicePublish(const char *name, const char *type, const char *domain, quint16 port)
{
	if (pri->dnssRef) {
		emit error(QZeroConf::serviceRegistrationFailed);
		return;
	}
	DNSServiceErrorType err = DNSServiceRegister(&pri->dnssRef,
      0,
      NULL,
			name,
			type,
			domain,
			NULL,
			qFromBigEndian<quint16>(port),
			pri->txt.size(), pri->txt.data(),
			(DNSServiceRegisterReply) QZeroConfPrivate::registerCallback, pri);

	if (err == kDNSServiceErr_NoError) {
		int sockfd = DNSServiceRefSockFD(pri->dnssRef);
		if (sockfd == -1) {
			pri->cleanUp(pri->dnssRef);
			emit error(QZeroConf::serviceRegistrationFailed);
		}
		else {
      // TODO: delete pri->bs here!
			pri->bs = new QSocketNotifier(sockfd, QSocketNotifier::Read, this);
			connect(pri->bs, SIGNAL(activated(int)), pri, SLOT(bsRead()));
		}
	}
	else {
		pri->cleanUp(pri->dnssRef);
		emit error(QZeroConf::serviceRegistrationFailed);
	}
}

void QZeroConf::stopServicePublish(void)
{
	pri->cleanUp(pri->dnssRef);
}

bool QZeroConf::publishExists(void)
{
	if (pri->dnssRef)
		return true;
	else
		return false;
}

void QZeroConf::addServiceTxtRecord(QString nameOnly)
{
	pri->txt.append((quint8) nameOnly.size());
	pri->txt.append(nameOnly.toUtf8());
}

void QZeroConf::addServiceTxtRecord(QString name, QString value)
{
	name.append("=");
	name.append(value);
	addServiceTxtRecord(name);
}

void QZeroConf::clearServiceTxtRecords()
{
	pri->txt.clear();
}

void QZeroConf::startBrowser(QString type, QAbstractSocket::NetworkLayerProtocol protocol)
{
	if (pri->browser) {
		emit error(QZeroConf::browserFailed);
		return;
	}

	LOGDEBUG << "Calling DNSServiceBrowse";

	switch (protocol) {
		case QAbstractSocket::IPv4Protocol: pri->protocol = kDNSServiceProtocol_IPv4; break;
		case QAbstractSocket::IPv6Protocol: pri->protocol = kDNSServiceProtocol_IPv6; break;
		case QAbstractSocket::AnyIPProtocol: pri->protocol = kDNSServiceProtocol_IPv4 | kDNSServiceProtocol_IPv6; break;
		default: pri->protocol = kDNSServiceProtocol_IPv4; break;
	};

	DNSServiceErrorType err = DNSServiceBrowse(&pri->browser, 0, 0, type.toUtf8(), 0, (DNSServiceBrowseReply) QZeroConfPrivate::browseCallback, pri);
	if (err != kDNSServiceErr_NoError) {
		LOGDEBUG << "DNSServiceBrowse failed! Returned:" << err;
		pri->cleanUp(pri->browser);
		emit error(QZeroConf::browserFailed);
		return;
	}

	int sockfd = DNSServiceRefSockFD(pri->browser);
	if (sockfd == -1) {
		LOGDEBUG << "DNSServiceRefSockFD failed! Returned:" << sockfd;
		pri->cleanUp(pri->browser);
		emit error(QZeroConf::browserFailed);
		return;
	}

	LOGDEBUG << "Successful DNSServiceBrowse, waiting on browserSocket: " << sockfd;
	delete pri->browserSocket;
	pri->browserSocket = new QSocketNotifier(sockfd, QSocketNotifier::Read, this);
	connect(pri->browserSocket, SIGNAL(activated(int)), pri, SLOT(browserRead()));
}

void QZeroConf::stopBrowser(void)
{
  pri->cleanUp(pri->addrInfo);
  pri->cleanUp(pri->resolver);
	pri->cleanUp(pri->browser);
}

bool QZeroConf::browserExists(void)
{
	if (pri->browser)
		return true;
	else
		return false;
}
