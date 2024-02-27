#include <QCoreApplication>

#include <cstddef>
#include <cstdint>
#include <cstdlib>
#include <cstring>
#include <stdexcept>
#include <utility>
#include <chrono>
#include <iostream>

#include <QString>
#include <QVector>
#include <QCryptographicHash>
#include <QObject>
#include <QWebSocket>
#include <QSocketNotifier>
#include <QTimer>

#include <fcntl.h>
#include <unistd.h>
#include <linux/if.h>
#include <linux/if_tun.h>
#include <netinet/in.h>
#include <sys/ioctl.h>

namespace {

constexpr auto kWebSocketPingPeriod = std::chrono::seconds(15);

} // namespace

class SysHandle
{
	static constexpr int INVALID_HANDLE = -1;
	int _handle = INVALID_HANDLE;

public:
	// читаем из .first, пишем в .second
	static std::pair<SysHandle, SysHandle> CreatePipe(int flags) {
		int fd[2] = { 0, 0 };
		if (::pipe2(fd, flags) != 0) {
			throw std::runtime_error{QStringLiteral(R"""(::pipe2(fd, %1) failed, errno=%2)""").arg(flags, 8, 16, QLatin1Char{'0'}).arg(errno).toStdString()};
		}
		return { SysHandle{fd[0]}, SysHandle{fd[1]} };
	}

	friend void swap(SysHandle& first, SysHandle& second) noexcept {
		std::swap(first._handle, second._handle);
	}

	explicit SysHandle(int handle)
		: _handle{ handle }
	{
		if (_handle == INVALID_HANDLE) {
			throw std::logic_error{"invalid handle on construction"};
		}
	}

	explicit SysHandle(const char* pathname, int flags)
		: _handle{ ::open(pathname, flags) }
	{
		if (_handle == INVALID_HANDLE) {
			throw std::runtime_error{QStringLiteral(R"""(::open("%1", %2) failed, errno=%3)""").arg(pathname).arg(flags, 8, 16, QLatin1Char{'0'}).arg(errno).toStdString()};
		}
	}

	~SysHandle() {
		if (_handle == INVALID_HANDLE) {
			return;
		}
		if (::close(_handle) != 0) {
			std::abort();
		}
	}

	void reset() {
		if (_handle == INVALID_HANDLE) {
			return;
		}
		if (::close(_handle) != 0) {
			throw std::runtime_error{QStringLiteral(R"""(::close(%1) failed, errno=%2)""").arg(_handle).arg(errno).toStdString()};
		}
		_handle = INVALID_HANDLE;
	}

	SysHandle() = default;
	SysHandle(const SysHandle&) = delete;
	SysHandle& operator=(const SysHandle&) = delete;
	SysHandle(SysHandle&& that) noexcept: SysHandle{} { swap(*this, that); }
	SysHandle& operator=(SysHandle&& that) noexcept { swap(*this, that); return *this; }

	operator int() const {
		if (_handle == INVALID_HANDLE) {
			throw std::logic_error{"invalid handle on usage"};
		}
		return _handle;
	}
};

::ifreq prepare_ifreq(const char* devname)
{
	::ifreq ifr;
	std::memset(&ifr, 0, sizeof(ifr));
	std::strncpy(ifr.ifr_name, devname, IFNAMSIZ);
	return ifr;
}

SysHandle tap_open(const char* devname)
{
	SysHandle fd{ "/dev/net/tun", O_RDWR };
	::ifreq ifr = prepare_ifreq(devname);
	ifr.ifr_flags = IFF_TAP | IFF_NO_PI;
	if (::ioctl(fd, TUNSETIFF, &ifr) != 0) {
		throw std::runtime_error{QStringLiteral(R"""(::ioctl(fd, TUNSETIFF, &ifr) failed, errno=%1)""").arg(errno).toStdString()};
	}
	return fd;
}

int get_if_mtu(const char* devname)
{
	SysHandle fd{ socket(AF_INET, SOCK_DGRAM, 0) };
	::ifreq ifr = prepare_ifreq(devname);
	if (::ioctl(fd, SIOCGIFMTU, &ifr) != 0) {
		throw std::runtime_error{QStringLiteral(R"""(::ioctl(fd, SIOCGIFMTU, &ifr) failed, errno=%1)""").arg(errno).toStdString()};
	}
	return ifr.ifr_mtu;
}

std::uint64_t get_if_hw_addr(const char* devname)
{
	SysHandle fd{ socket(AF_INET, SOCK_DGRAM, 0) };
	::ifreq ifr = prepare_ifreq(devname);
	if (::ioctl(fd, SIOCGIFHWADDR, &ifr) != 0) {
		throw std::runtime_error{QStringLiteral(R"""(::ioctl(fd, SIOCGIFHWADDR, &ifr) failed, errno=%1)""").arg(errno).toStdString()};
	}
	std::uint64_t mac = 0;
	for (std::size_t i = 0; i < 6; ++i) {
		mac = (mac << 8) | static_cast<std::uint64_t>(static_cast<std::uint8_t>(ifr.ifr_hwaddr.sa_data[i]));
	}
	return mac;
}

QString macToString(std::uint64_t mac)
{
	return QStringLiteral("%1:%2:%3:%4:%5:%6")
		.arg((mac >> 40) & 0xff, 2, 16, QLatin1Char('0'))
		.arg((mac >> 32) & 0xff, 2, 16, QLatin1Char('0'))
		.arg((mac >> 24) & 0xff, 2, 16, QLatin1Char('0'))
		.arg((mac >> 16) & 0xff, 2, 16, QLatin1Char('0'))
		.arg((mac >>  8) & 0xff, 2, 16, QLatin1Char('0'))
		.arg( mac        & 0xff, 2, 16, QLatin1Char('0'))
	;
}

std::uint32_t get_if_ip_addr(const char* devname)
{
	SysHandle fd{ socket(AF_INET, SOCK_DGRAM, 0) };
	::ifreq ifr = prepare_ifreq(devname);
	if (::ioctl(fd, SIOCGIFADDR, &ifr) != 0) {
		throw std::runtime_error{QStringLiteral(R"""(::ioctl(fd, SIOCGIFADDR, &ifr) failed, errno=%1)""").arg(errno).toStdString()};
	}
	std::uint32_t ip = 0;
	for (std::size_t i = 0; i < 4; ++i) {
		ip = (ip << 8) | static_cast<std::uint32_t>(static_cast<std::uint8_t>(ifr.ifr_addr.sa_data[2 + i]));
	}
	return ip;
}

QString ipToString(std::uint32_t ip)
{
	return QStringLiteral("%1.%2.%3.%4")
		.arg((ip >> 24) & 0xff)
		.arg((ip >> 16) & 0xff)
		.arg((ip >>  8) & 0xff)
		.arg( ip        & 0xff)
		;
}

int main(int argc, char *argv[])
try {
	// будем исповедовать идеологию "падать при любой ошибке". Восстановление соединения отдаём наверх, в systemd или иной механизм перезапуска приложения

	QCoreApplication app(argc, argv);

	const QByteArray wsnDevice = qgetenv("WSN_DEVICE");
	const QByteArray wsnServer = qgetenv("WSN_SERVER");
	const QByteArray wsnSecret = qgetenv("WSN_SECRET");

	std::cout << "WSN_DEVICE: " << wsnDevice.data() << std::endl;
	std::cout << "WSN_SERVER: " << wsnServer.data() << std::endl;

	enum class State {
		DISCONNECTED
	  , WAIT_FOR_CHALLENGE
	  , WAIT_FOR_FRAME
	};
	State state = State::DISCONNECTED;

	const SysHandle tapHandle = tap_open(wsnDevice.data());
	const int             mtu = get_if_mtu(wsnDevice.data());
	const std::uint64_t   mac = get_if_hw_addr(wsnDevice.data());
	const std::uint32_t    ip = get_if_ip_addr(wsnDevice.data());

	std::cout << "mtu: " << mtu << std::endl;
	std::cout << "mac: " << macToString(mac).toStdString() << std::endl;
	std::cout << " ip: " << ipToString(ip).toStdString() << std::endl;

	QWebSocket webSocket;
	QObject::connect(&webSocket, &QWebSocket::disconnected, &app, [&state]{
		if (state == State::DISCONNECTED) {
			return;
		}
		state = State::DISCONNECTED;
		std::cout << "websocket disconnected" << std::endl;
		QCoreApplication::quit();
	}, Qt::QueuedConnection);
	QObject::connect(&webSocket, qOverload<QAbstractSocket::SocketError>(&QWebSocket::error), &app, [&state](QAbstractSocket::SocketError error){
		if (state == State::DISCONNECTED) {
			return;
		}
		state = State::DISCONNECTED;
		std::cerr << "websocket error: " << static_cast<int>(error) << std::endl;
		QCoreApplication::quit();
	}, Qt::QueuedConnection);
	QObject::connect(&webSocket, &QWebSocket::connected, &app, [&state]{
		if (state != State::DISCONNECTED) {
			return;
		}
		state = State::WAIT_FOR_CHALLENGE;
		std::cout << "websocket connected" << std::endl;
	}, Qt::QueuedConnection);
	QObject::connect(&webSocket, &QWebSocket::binaryFrameReceived, &app, [&wsnSecret, &mac, &state, &tapHandle, &webSocket](const QByteArray& message){
		if (state == State::WAIT_FOR_CHALLENGE) {
			QCryptographicHash hash{ QCryptographicHash::Sha256 };
			hash.addData(message);
			hash.addData(wsnSecret);
			hash.addData(message);
			const QByteArray response = hash.result();
			if (webSocket.sendBinaryMessage(response) != response.length()) {
				std::cerr << "response send failed" << std::endl;
				QCoreApplication::quit();
				return;
			}
			QByteArray macBytes;
			macBytes.append((mac >> 40) & 0xff);
			macBytes.append((mac >> 32) & 0xff);
			macBytes.append((mac >> 24) & 0xff);
			macBytes.append((mac >> 16) & 0xff);
			macBytes.append((mac >>  8) & 0xff);
			macBytes.append( mac        & 0xff);
			if (webSocket.sendBinaryMessage(macBytes) != macBytes.length()) {
				std::cerr << "response mac failed" << std::endl;
				QCoreApplication::quit();
				return;
			}
			state = State::WAIT_FOR_FRAME;
			return;
		}
		if (state == State::WAIT_FOR_FRAME) {
			if (::write(tapHandle, message.constData(), message.length()) != message.length()) {
				std::cerr << "tap write failed, errno=" << errno << std::endl;
				QCoreApplication::quit();
				return;
			}
			return;
		}
	}, Qt::QueuedConnection);
	webSocket.open(QUrl{QString::fromUtf8(wsnServer)});

	QSocketNotifier tapNotifier{ tapHandle, QSocketNotifier::Read };
	QObject::connect(&tapNotifier, &QSocketNotifier::activated, &app, [&mtu, &state, &tapHandle, &webSocket](QSocketDescriptor, QSocketNotifier::Type activationEvent){
		if (activationEvent == QSocketNotifier::Write) {
			return;
		}
		if (activationEvent == QSocketNotifier::Exception) {
			std::cerr << "QSocketNotifier::Exception" << std::endl;
			QCoreApplication::quit();
			return;
		}

		const int maxFrameSize = mtu + 14;
		QByteArray buffer;
		buffer.resize(maxFrameSize + 256);

		const auto n_bytes = ::read(tapHandle, buffer.data(), buffer.length());
		if (n_bytes == 0) {
			return;
		}
		if (n_bytes < 0) {
			std::cerr << "tap read failed, errno=" << errno << std::endl;
			QCoreApplication::quit();
			return;
		}
		buffer.resize(n_bytes);

		if (n_bytes > maxFrameSize) {
			std::cerr << "got too big frame: " << n_bytes << std::endl;
			QCoreApplication::quit();
			return;
		}
		if (state != State::WAIT_FOR_FRAME) {
			return;
		}
		if (webSocket.sendBinaryMessage(buffer) != n_bytes) {
			std::cerr << "websocket write failed" << std::endl;
			QCoreApplication::quit();
			return;
		}
	}, Qt::DirectConnection); //! обязательно DirectConnection, иначе будут повторные срабатывания сигнала

	QTimer pingTimer;
	QObject::connect(&pingTimer, &QTimer::timeout, &webSocket, [&webSocket]{
		webSocket.ping();
	}, Qt::QueuedConnection);
	pingTimer.start(kWebSocketPingPeriod); // да, запускаем до получения connected-state

	return app.exec();
}
catch (std::exception& e) {
	std::cerr << e.what() << std::endl;
	return EXIT_FAILURE;
}
