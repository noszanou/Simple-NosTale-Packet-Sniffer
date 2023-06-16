using PacketDotNet;
using System.Text;

namespace Simple_NosTale_Packet_Sniffer
{
    public class LoginPacketExtension
    {
        public static string ServerToClient(in ReadOnlySpan<byte> str)
        {
            try
            {
                var output = new StringBuilder(str.Length);
                foreach (var c in str)
                {
                    output.Append(Convert.ToChar((byte)((c - 0xF) % 256)));
                }

                return output.ToString();
            }
            catch
            {
                return string.Empty;
            }
        }


        public static string ClientToServer(in ReadOnlySpan<byte> bytes)
        {
            try
            {
                var output = new StringBuilder(bytes.Length);
                foreach (var c in bytes)
                {
                    output.Append(Convert.ToChar(((c - 0xF) ^ 0xC3) & 0xFF));
                }

                return output.ToString();
            }
            catch
            {
                return string.Empty;
            }
        }
    }
}