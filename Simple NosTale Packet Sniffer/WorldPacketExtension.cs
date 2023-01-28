using System.Text;

namespace Simple_NosTale_Packet_Sniffer
{
    public class WorldPacketExtension
    {
        private static readonly char[] Keys = { ' ', '-', '.', '0', '1', '2', '3', '4', '5', '6', '7', '8', '9', 'n' };

        public static List<string> ServerToClient(byte[] bytes)
        {
            var output = new List<string>();

            var currentPacket = "";
            var index = 0;

            while (index < bytes.Length)
            {
                byte currentByte = bytes[index];
                index++;

                if (currentByte == 0xFF)
                {
                    output.Add(currentPacket);
                    currentPacket = "";
                    continue;
                }

                var length = (byte)(currentByte & 0x7F);

                if ((currentByte & 0x80) != 0)
                {
                    while (length != 0)
                    {
                        if (index <= bytes.Length)
                        {
                            currentByte = bytes[index];
                            index++;

                            var firstIndex = (byte)(((currentByte & 0xF0u) >> 4) - 1);
                            var first = (byte)(firstIndex != 255 ? firstIndex != 14 ? Keys[firstIndex] : '\u0000' : '?');
                            if (first != 0x6E)
                                currentPacket += Convert.ToChar(first);

                            if (length <= 1)
                                break;

                            var secondIndex = (byte)((currentByte & 0xF) - 1);
                            var second = (byte)(secondIndex != 255 ? secondIndex != 14 ? Keys[secondIndex] : '\u0000' : '?');
                            if (second != 0x6E)
                                currentPacket += Convert.ToChar(second);

                            length -= 2;
                        }
                        else
                        {
                            length--;
                        }
                    }
                }
                else
                {
                    while (length != 0)
                    {
                        if (index < bytes.Length)
                        {
                            currentPacket += Convert.ToChar(bytes[index] ^ 0xFF);
                            index++;
                        }
                        else if (index == bytes.Length)
                        {
                            currentPacket += Convert.ToChar(0xFF);
                            index++;
                        }

                        length--;
                    }
                }
            }
            return output;
        }

        public static string InitializeEncryptionKey(byte[] data)
        {
            try
            {
                StringBuilder builder = new StringBuilder();
                for (int i = 1; i < data.Length; i++)
                {
                    if (Convert.ToChar(data[i]) == 0xE)
                    {
                        return builder.ToString();
                    }

                    int firstByte = Convert.ToInt32(data[i] - 0xF);
                    int secondByte = firstByte;
                    secondByte &= 0xF0;
                    firstByte = Convert.ToInt32(firstByte - secondByte);
                    secondByte >>= 0x4;

                    switch (secondByte)
                    {
                        case 0:
                        case 1:
                            builder.Append(' ');
                            break;

                        case 2:
                            builder.Append('-');
                            break;

                        case 3:
                            builder.Append('.');
                            break;

                        default:
                            secondByte += 0x2C;
                            builder.Append(Convert.ToChar(secondByte));
                            break;
                    }

                    switch (firstByte)
                    {
                        case 0:
                        case 1:
                            builder.Append(' ');
                            break;

                        case 2:
                            builder.Append('-');
                            break;

                        case 3:
                            builder.Append('.');
                            break;

                        default:
                            firstByte += 0x2C;
                            builder.Append(Convert.ToChar(firstByte));
                            break;
                    }
                }

                return builder.ToString();
            }
            catch (OverflowException)
            {
                return "";
            }
        }

        private static string Decrypt2(string str)
        {
            List<byte> receiveData = new List<byte>();
            char[] table = { ' ', '-', '.', '0', '1', '2', '3', '4', '5', '6', '7', '8', '9', 'n' };
            for (int i = 0; i < str.Length; i++)
            {
                if (str[i] <= 0x7A)
                {
                    int len = str[i];

                    for (int j = 0; j < len; j++)
                    {
                        i++;

                        try
                        {
                            receiveData.Add(unchecked((byte)(str[i] ^ 0xFF)));
                        }
                        catch (Exception)
                        {
                            receiveData.Add(255);
                        }
                    }
                }
                else
                {
                    int len = str[i];
                    len &= 0x7F;

                    for (int j = 0; j < len; j++)
                    {
                        i++;
                        int highbyte;
                        try
                        {
                            highbyte = str[i];
                        }
                        catch (Exception)
                        {
                            highbyte = 0;
                        }
                        highbyte &= 0xF0;
                        highbyte >>= 0x4;

                        int lowbyte;
                        try
                        {
                            lowbyte = str[i];
                        }
                        catch (Exception)
                        {
                            lowbyte = 0;
                        }
                        lowbyte &= 0x0F;

                        if (highbyte != 0x0 && highbyte != 0xF)
                        {
                            receiveData.Add(unchecked((byte)table[highbyte - 1]));
                            j++;
                        }

                        if (lowbyte != 0x0 && lowbyte != 0xF)
                        {
                            receiveData.Add(unchecked((byte)table[lowbyte - 1]));
                        }
                    }
                }
            }
            return Encoding.UTF8.GetString(Encoding.Convert(Encoding.Default, Encoding.UTF8, receiveData.ToArray()));
        }

        public static string ClientToServer(byte[] data, int sessionId = 0)
        {
            int sessionKey = sessionId & 0xFF;
            byte sessionNumber = unchecked((byte)(sessionId >> 6));
            sessionNumber &= 0xFF;
            sessionNumber &= unchecked((byte)0x80000003);

            StringBuilder decryptPart = new StringBuilder();
            switch (sessionNumber)
            {
                case 0:

                    foreach (byte character in data)
                    {
                        byte firstbyte = unchecked((byte)(sessionKey + 0x40));
                        byte highbyte = unchecked((byte)(character - firstbyte));
                        decryptPart.Append((char)highbyte);
                    }
                    break;

                case 1:
                    foreach (byte character in data)
                    {
                        byte firstbyte = unchecked((byte)(sessionKey + 0x40));
                        byte highbyte = unchecked((byte)(character + firstbyte));
                        decryptPart.Append((char)highbyte);
                    }
                    break;

                case 2:
                    foreach (byte character in data)
                    {
                        byte firstbyte = unchecked((byte)(sessionKey + 0x40));
                        byte highbyte = unchecked((byte)(character - firstbyte ^ 0xC3));
                        decryptPart.Append((char)highbyte);
                    }
                    break;

                case 3:
                    foreach (byte character in data)
                    {
                        byte firstbyte = unchecked((byte)(sessionKey + 0x40));
                        byte highbyte = unchecked((byte)(character + firstbyte ^ 0xC3));
                        decryptPart.Append((char)highbyte);
                    }
                    break;

                default:
                    decryptPart.Append((char)0xF);
                    break;
            }

            StringBuilder decrypted = new StringBuilder();

            string[] encryptedSplit = decryptPart.ToString().Split((char)0xFF);
            for (int i = 0; i < encryptedSplit.Length; i++)
            {
                decrypted.Append(Decrypt2(encryptedSplit[i]));
                if (i < encryptedSplit.Length - 2)
                {
                    decrypted.Append((char)0xFF);
                }
            }

            return decrypted.ToString();
        }

    }
}