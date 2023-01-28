namespace Simple_NosTale_Packet_Sniffer
{
    public class Program
    {
        private static int LastPacketId { get; set; }
        private static int SessionId { get; set; }

        public static void Main(string[] args)
        {
            Console.WriteLine("Hello, World!");
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

                    if (packetsplit[1] != "0") // Useless packet its just sended to server to tell TcpCLient is still active
                    {
                        Console.WriteLine("[WORLD][SEND] {0}", packetstring);
                    }
                }
            }
        }
    }
}