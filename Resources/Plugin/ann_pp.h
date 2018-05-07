#include <map>
#include <string>

class Connection
{
public:
    Connection() { };

    void setClient (std::string ip)
    { client_ip = ip; }

    void setServer (std::string ip)
    { server_ip = ip; }

    void setClientPort (int port)
    { client_port = port; }

    void setServerPort (int port)
    { server_port = port; }

    void addSourceBytes (int amount)
    { totalSourceBytes += amount; }

    void addSourcePackets ()
    { totalSourcePackets++; }

    void addDestinationBytes (int amount)
    { totalDestinationBytes += amount; }

    void addDestinationPackets ()
    { totalDestinationPackets++; }

    void setFirstTimestamp (int timestamp)
    { firstTimestamp = timestamp; }

    void setLastTimestamp (int timestamp)
    { lastTimestamp = timestamp; }

    void setProtocol (std::string name)
    { protocol = name; }

    std::string getProtocol ()
    { return protocol; }

    void setDirection (std::string dir)
    { direction = dir; }

    void setProtocolTimeout (int timeout)
    { protocolTimeout = timeout; }

    int getProtocolTimeout () const
    { return protocolTimeout; }

    void setStatus (std::string s)
    { status = s; }

    std::string getStatus () const
    { return status; }
public:
    std::string client_ip = "", server_ip = "";
    int client_port = 0, server_port = 0;

    int totalSourceBytes = 0;
    int totalSourcePackets = 0;

    int totalDestinationBytes = 0;
    int totalDestinationPackets = 0;

    int firstTimestamp = 0;
    int lastTimestamp = 0;

    std::string sourceTCPFlags = "N/A";
    std::string destinationTCPFlags = "N/A";

    std::string protocol = "Unknown";
    std::string direction = "N/A";

    int protocolTimeout = 0;

    std::string status = "Unknown";

    int s_ACK = 0, s_PSH = 0, s_RST = 0, s_SYN = 0, s_FIN = 0;
    int d_ACK = 0, d_PSH = 0, d_RST = 0, d_SYN = 0, d_FIN = 0;
};

class ConnectionsManager
{
public:
    ConnectionsManager() { };
    void displayConnections();
public:
    std::map<std::string, Connection> connections;
    std::map<std::string, Connection>::iterator it;
};
