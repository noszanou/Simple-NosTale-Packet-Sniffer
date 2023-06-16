using PacketDotNet;
using SharpPcap;
using System.Net;

namespace Simple_NosTale_Packet_Sniffer
{
    public class Program
    {
        private static int LastPacketId { get; set; }
        private static int SessionId { get; set; }

        public static void Main(string[] args)
        {
            var devices = CaptureDeviceList.Instance;

            if (devices.Count < 1)
            {
                Console.WriteLine("No devices were found on this machine");
                Console.ReadLine();
                return;
            }

            var device = devices.First();
            device.OnPacketArrival += Device_OnPacketArrival;
            device.Open(DeviceModes.Promiscuous, 1000);

            Console.WriteLine("-- Listening on {0} Network", device.Description);

            device.StartCapture();

            Console.ReadLine();

            device.StopCapture();
            device.Close();
        }

        private static void Device_OnPacketArrival(object sender, PacketCapture e)
        {
            var rawPacket = e.GetPacket();
            var packet = Packet.ParsePacket(rawPacket.LinkLayerType, rawPacket.Data);

            var tcpPacket = packet.Extract<TcpPacket>();
            if (tcpPacket == null)
            {
                return;
            }
            var ipPacket = (IPPacket)((EthernetPacket)packet).PayloadPacket;
            IPAddress srcIp = ipPacket.SourceAddress;
            IPAddress dstIp = ipPacket.DestinationAddress;
            Packet payloadPacket = tcpPacket;
            byte[] data = payloadPacket.PayloadData;

            if (data.Length <= 0 && (data.Length != 1 || data[0] == 0x00)) return;

            if (srcIp.ToString().Equals(StaticConfig.GameForgeLoginIp))
            {
                ParseLoginReceivePacket(data);
                return;
            }

            if (dstIp.ToString().Equals(StaticConfig.GameForgeLoginIp))
            {
                ParseLoginSendPacket(data);
                return;
            }

            if (srcIp.ToString().Equals(StaticConfig.GameForgeAsgobasServerIp))
            {
                ParseWorldReceivePacket(data);
                return;
            }

            if (dstIp.ToString().Equals(StaticConfig.GameForgeAsgobasServerIp))
            {
                ParseWorldSendPacket(data);
                return;
            }
        }

        private static void ParseLoginReceivePacket(byte[] data)
        {
            Console.WriteLine("[LOGIN][RECV] {0}", LoginPacketExtension.ServerToClient(data));
        }

        private static void ParseWorldReceivePacket(byte[] data)
        {
            var pac = WorldPacketExtension.ServerToClient(data);
            foreach (var i in pac)
            {
                Console.WriteLine("[WORLD][RECV] {0}", i);
            }
        }

        private static void ParseLoginSendPacket(byte[] data)
        {
            Console.WriteLine("[LOGIN][SEND] {0}", LoginPacketExtension.ClientToServer(data));
        }

        private static void ParseWorldSendPacket(byte[] data)
        {
            if (SessionId == 0)
            {
                string sessionPacket = WorldPacketExtension.InitializeEncryptionKey(data);

                string[] sessionParts = sessionPacket.Split(' ');

                if (sessionParts.Length == 0)
                {
                    return;
                }

                if (!int.TryParse(sessionParts[0], out int packetId))
                {
                    return;
                }

                LastPacketId = packetId;
                if (sessionParts.Length < 2)
                {
                    return;
                }

                if (int.TryParse(sessionParts[1].Split('\\').FirstOrDefault(), out int sessid))
                {
                    SessionId = sessid;
                }

                return;
            }

            string packetConcatenated = WorldPacketExtension.ClientToServer(data, SessionId);

            foreach (string pd in packetConcatenated.Split(new[] { (char)0xFF }, StringSplitOptions.RemoveEmptyEntries))
            {
                string packetstring = pd.Replace('^', ' ');
                string[] packetsplit = packetstring.Split(' ');
                string nextRawPacketId = packetsplit[0];

                if (!int.TryParse(nextRawPacketId, out int nextPacketId) && nextPacketId != LastPacketId + 1)
                {
                    return;
                }

                if (nextPacketId == 0)
                {
                    if (LastPacketId == ushort.MaxValue)
                    {
                        LastPacketId = nextPacketId;
                    }
                }
                else
                {
                    LastPacketId = nextPacketId;
                }

                if (packetsplit.Length > 1)
                {
                    if (packetsplit[1].Length >= 1 && (packetsplit[1][0] == '/' || packetsplit[1][0] == ':' || packetsplit[1][0] == ';'))
                    {
                        packetsplit[1] = packetsplit[1][0].ToString();
                        packetstring = pd.Insert(pd.IndexOf(' ') + 2, " ");
                    }

                    if (packetsplit[1] == "0") // Useless packet its just sended to server to tell TcpCLient is still active
                    {
                        continue;
                    }

                    Console.WriteLine("[WORLD][SEND] {0}", packetstring);
                }
            }
        }
    }
}