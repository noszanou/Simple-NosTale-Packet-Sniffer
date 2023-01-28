using System.Text;

namespace Simple_NosTale_Packet_Sniffer
{
    public class LoginPacketExtension
    {
        public static string ServerToClient(byte[] data)
        {
            try
            {
                StringBuilder builder = new StringBuilder();
                foreach (byte character in data)
                {
                    if (character > 14)
                    {
                        builder.Append(Convert.ToChar((character - 15) ^ 195));
                    }
                    else
                    {
                        builder.Append(Convert.ToChar((256 - (15 - character)) ^ 195));
                    }
                }
                return builder.ToString();
            }
            catch (Exception)
            {
                return "";
            }
        }

        public static string ClientToServer(byte[] bytes)
        {
            var output = "";
            for (var i = 0; i < bytes.Length; i++)
            {
                output += Convert.ToChar(bytes[i] - 0xF);
            }
            return output;
        }
    }
}