#include <atomic>
#include <cstddef>
#include <cstdint>
#include <cstdlib>
#include <csignal>
#include <cstring>
#include <stdexcept>
#include <chrono>
#include <thread>
#include <utility>
#include <array>
#include <vector>
#include <iostream>

#include <fcntl.h>
#include <unistd.h>
#include <sys/socket.h>
#include <sys/types.h>
#include <sys/ioctl.h>
#include <linux/if.h>
#include <linux/if_tun.h>
#include <netinet/in.h>

class SysHandle
{
	static constexpr int INVALID_HANDLE = -1;
	int _handle = INVALID_HANDLE;

public:
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
			throw std::runtime_error{"::open(pathname, flags) failed"};
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
			throw std::runtime_error{"::close(_handle) failed"};
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

::sockaddr_in prepare_sockaddr_in(std::uint16_t port)
{
	::sockaddr_in addr;
	std::memset(&addr, 0, sizeof(addr));
	addr.sin_family = AF_INET;
	addr.sin_addr.s_addr = ::htonl(0x7f000001u); // 127.0.0.1
	addr.sin_port        = ::htons(port);
	return addr;
}

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
		throw std::runtime_error{"::ioctl(fd, TUNSETIFF, &ifr) failed"};
	}
	return fd;
}

int get_if_mtu(const char* devname)
{
	SysHandle fd{ socket(AF_INET, SOCK_DGRAM, 0) };
	::ifreq ifr = prepare_ifreq(devname);
	if (::ioctl(fd, SIOCGIFMTU, &ifr) != 0) {
		throw std::runtime_error{"::ioctl(fd, SIOCGIFMTU, &ifr) failed"};
	}
	return ifr.ifr_mtu;
}

std::uint64_t get_if_hw_addr(const char* devname)
{
	SysHandle fd{ socket(AF_INET, SOCK_DGRAM, 0) };
	::ifreq ifr = prepare_ifreq(devname);
	if (::ioctl(fd, SIOCGIFHWADDR, &ifr) != 0) {
		throw std::runtime_error{"::ioctl(fd, SIOCGIFHWADDR, &ifr) failed"};
	}
	std::uint64_t mac = 0;
	for (std::size_t i = 0; i < 6; ++i) {
		mac = (mac << 8) | static_cast<std::uint64_t>(static_cast<std::uint8_t>(ifr.ifr_hwaddr.sa_data[i]));
	}
	return mac;
}

std::uint32_t get_if_ip_addr(const char* devname)
{
	SysHandle fd{ socket(AF_INET, SOCK_DGRAM, 0) };
	::ifreq ifr = prepare_ifreq(devname);
	if (::ioctl(fd, SIOCGIFADDR, &ifr) != 0) {
		throw std::runtime_error{"::ioctl(fd, SIOCGIFADDR, &ifr) failed"};
	}
	std::uint32_t ip = 0;
	for (std::size_t i = 0; i < 4; ++i) {
		ip = (ip << 8) | static_cast<std::uint32_t>(static_cast<std::uint8_t>(ifr.ifr_addr.sa_data[2 + i]));
	}
	return ip;
}

std::uint64_t bytes_to_uint64(const std::vector<char>& v)
{
	return 
		(static_cast<std::uint64_t>(static_cast<std::uint8_t>(v[0])) << 56) |
		(static_cast<std::uint64_t>(static_cast<std::uint8_t>(v[1])) << 48) |
		(static_cast<std::uint64_t>(static_cast<std::uint8_t>(v[2])) << 40) |
		(static_cast<std::uint64_t>(static_cast<std::uint8_t>(v[3])) << 32) |
		(static_cast<std::uint64_t>(static_cast<std::uint8_t>(v[4])) << 24) |
		(static_cast<std::uint64_t>(static_cast<std::uint8_t>(v[5])) << 16) |
		(static_cast<std::uint64_t>(static_cast<std::uint8_t>(v[6])) <<  8) |
		(static_cast<std::uint64_t>(static_cast<std::uint8_t>(v[7])));
}

std::array<char, 8> uint64_to_bytes(std::uint64_t v)
{
	return std::array<char, 8>{{
		static_cast<char>(static_cast<std::uint8_t>(v >> 56)),
		static_cast<char>(static_cast<std::uint8_t>(v >> 48)),
		static_cast<char>(static_cast<std::uint8_t>(v >> 40)),
		static_cast<char>(static_cast<std::uint8_t>(v >> 32)),
		static_cast<char>(static_cast<std::uint8_t>(v >> 24)),
		static_cast<char>(static_cast<std::uint8_t>(v >> 16)),
		static_cast<char>(static_cast<std::uint8_t>(v >>  8)),
		static_cast<char>(static_cast<std::uint8_t>(v))
	}};
}

std::vector<char> mac_to_vec(std::uint64_t mac)
{
	return std::vector<char>{
		static_cast<char>(static_cast<std::uint8_t>(mac >> 40)),
		static_cast<char>(static_cast<std::uint8_t>(mac >> 32)),
		static_cast<char>(static_cast<std::uint8_t>(mac >> 24)),
		static_cast<char>(static_cast<std::uint8_t>(mac >> 16)),
		static_cast<char>(static_cast<std::uint8_t>(mac >>  8)),
		static_cast<char>(static_cast<std::uint8_t>(mac))
	};
}

std::string to_hex(std::uint8_t mac)
{
	static const std::array<char, 16> digits{
		'0', '1', '2', '3', '4', '5', '6', '7',
		'8', '9', 'a', 'b', 'c', 'd', 'e', 'f'
	};
	std::string result;
	result += digits[(mac >> 4) & 0x0f];
	result += digits[ mac       & 0x0f];
	return result;
}

std::string mac_to_string(std::uint64_t mac)
{
	std::string result;
	result += to_hex((mac >> 40) & 0xff);
	result += ':';
	result += to_hex((mac >> 32) & 0xff);
	result += ':';
	result += to_hex((mac >> 24) & 0xff);
	result += ':';
	result += to_hex((mac >> 16) & 0xff);
	result += ':';
	result += to_hex((mac >>  8) & 0xff);
	result += ':';
	result += to_hex( mac        & 0xff);
	return result;
}

std::string ip_to_string(std::uint32_t ip)
{
	std::string result;
	result += std::to_string((ip >> 24) & 0xff);
	result += '.';
	result += std::to_string((ip >> 16) & 0xff);
	result += '.';
	result += std::to_string((ip >>  8) & 0xff);
	result += '.';
	result += std::to_string( ip        & 0xff);
	return result;
}

bool read_fd(int fd, bool read_full_buffer, std::vector<char>& buffer) noexcept
{
	std::size_t n = 0;
	do {
		const auto result = ::read(fd, buffer.data() + n, buffer.size() - n);
		if (result <= 0) {
			return false;
		}
		n += static_cast<std::size_t>(result);
	} while (read_full_buffer && n != buffer.size());
	buffer.resize(n);
	return true;
}

bool write_fd(int fd, bool write_full_buffer, const char* buffer_data, std::size_t buffer_size) noexcept
{
	std::size_t n = 0;
	do {
		const auto result = ::write(fd, buffer_data + n, buffer_size - n);
		if (result <= 0) {
			return false;
		}
		n += static_cast<std::size_t>(result);
	} while (write_full_buffer && n != buffer_size);
	return n == buffer_size;
}

bool read_socket(int socket, std::vector<char>& buffer) noexcept
{
	buffer.resize(8);
	if (!read_fd(socket, true, buffer)) {
		return false;
	}
	const std::uint64_t length = bytes_to_uint64(buffer);
	if (length > 8192) {
		return false;
	}
	buffer.resize(length);
	return read_fd(socket, true, buffer);
}

bool write_socket(int socket, const std::vector<char>& buffer) noexcept
{
	const std::array<char, 8> tmp = uint64_to_bytes(buffer.size());
	if (!write_fd(socket, true, tmp.data(), 8)) {
		return false;
	}
	return write_fd(socket, true, buffer.data(), buffer.size());
}

int main()
try {
	const std::string wsnDevice = std::getenv("WSN_DEVICE");
	const int wsnPort = std::stoi(std::getenv("WSN_LISTEN"));

	std::cout << "WSN_DEVICE: " << wsnDevice << std::endl;
	std::cout << "WSN_LISTEN: " << "127.0.0.1:" << wsnPort << std::endl;

	const SysHandle tapHandle = tap_open(wsnDevice.c_str());
	const int             mtu = get_if_mtu(wsnDevice.c_str());
	const std::uint64_t   mac = get_if_hw_addr(wsnDevice.c_str());
//	const std::uint32_t    ip = get_if_ip_addr(wsnDevice.c_str());

	std::cout << "mtu: " << mtu << std::endl;
	std::cout << "mac: " << mac_to_string(mac) << std::endl;
//	std::cout << " ip: " << ip_to_string(ip) << std::endl;

	const SysHandle sfd{ ::socket(AF_INET, SOCK_STREAM, 0) };
	const ::sockaddr_in saddr = prepare_sockaddr_in(wsnPort);
	if (::bind(sfd, reinterpret_cast<const ::sockaddr*>(&saddr), sizeof(saddr)) != 0) {
		throw std::runtime_error{"::bind failed"};
	}
	if (::listen(sfd, 1) != 0) {
		throw std::runtime_error{"::listen failed"};
	}

	static std::atomic<int> client{0}; // static to be accessible in signal handlers

	signal(SIGPIPE, SIG_IGN);
	std::signal(SIGINT,  +[](int){ client.store(-1); });
	std::signal(SIGTERM, +[](int){ client.store(-1); });

	std::thread tx_thread{[&tapHandle]{
		std::vector<char> buffer;
		while (client.load() != -1) {
			buffer.resize(8192);
			if (!read_fd(tapHandle, false, buffer)) {
				client.store(-1);
				break;
			}
			const int socket = client.load();
			if (socket == -1) {
				break;
			}
			if (socket == 0) {
				continue;
			}
			if (!write_socket(socket, buffer)) {
				client.store(0);
				continue;
			}
		}
	}};

	std::thread rx_thread{[&tapHandle]{
		std::vector<char> buffer;
		while (client.load() != -1) {
			const int socket = client.load();
			if (socket == -1) {
				break;
			}
			if (socket == 0) {
				std::this_thread::sleep_for(std::chrono::seconds(1));
				continue;
			}
			if (!read_socket(socket, buffer)) {
				client.store(0);
				continue;
			}
			if (!write_fd(tapHandle, false, buffer.data(), buffer.size())) {
				client.store(-1);
				break;
			}
		}
	}};

	try {
		while (true) {
			const SysHandle cfd{ ::accept(sfd, nullptr, nullptr) };
			std::cout << "client connected" << std::endl;

			if (!write_socket(cfd, mac_to_vec(mac))) {
				continue;
			}

			client.store(cfd);
			while (true) {
				const int socket = client.load();
				if (socket == -1 || socket == 0) {
					break;
				}
				std::this_thread::sleep_for(std::chrono::seconds(1));
			}
			if (client.load() == -1) {
				break;
			}
		}
	}
	catch (...) {
		client.store(-1);
		rx_thread.join();
		tx_thread.join();
		throw;
	}

	rx_thread.join();
	tx_thread.join();
	std::cout << "EXIT_SUCCESS" << std::endl;
	return EXIT_SUCCESS;
}
catch (std::exception& e) {
	std::cerr << e.what() << std::endl;
	std::cout << "EXIT_FAILURE" << std::endl;
	return EXIT_FAILURE;
}
