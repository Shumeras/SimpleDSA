using System.Numerics;
using System.Text.Json;
using System.IO;
using System;
using System.Text;

namespace DSA
{
    static class Utilities
    {
 
        private class PublicKeySerialized
        {
            public string p { get; set; }
            public string q { get; set; }
            public string a { get; set; }
            public string b { get; set; }
        }

        private class PrivateKeySerialized
        {
            public string d { get; set; }
        }

        public class SignedMessageSerialized 
        { 
            public string r { get; set; }
            public string s { get; set; } 
            public string message { get; set;}
        }

        public static bool SaveToFile(string fileDir, string data)
        {
            try{
                File.WriteAllText(fileDir, data, Encoding.UTF8);
            }
            catch (Exception e)
            {
                System.Console.WriteLine(e.ToString());
                return false;
            }
            return true;
        }

        public static string LoadFromFile(string fileDir)
        {
            var result = "";
            try{
                result = File.ReadAllText(fileDir);
            }
            catch (Exception e)
            {
                System.Console.WriteLine(e.ToString());
            }
            return result;
        }

        public static string SerializePublicKey((BigInteger p, BigInteger q, BigInteger a, BigInteger b) key, string fileDir = null)
        {
            var opt = new JsonSerializerOptions() {WriteIndented=true};
            string result = JsonSerializer.Serialize(
                new PublicKeySerialized() {
                    p = key.p.ToString(),
                    q = key.q.ToString(),
                    a = key.a.ToString(),
                    b = key.b.ToString()
                }, opt);
            
            if(fileDir != null && fileDir.Length > 0)
                SaveToFile(fileDir, result);
            
            return result;
        }

        public static (BigInteger p, BigInteger q, BigInteger a, BigInteger b) DeserializePublicKey(string data)
        {
            var key = JsonSerializer.Deserialize<PublicKeySerialized>(data);
            return (BigInteger.Parse(key.p), BigInteger.Parse(key.q), BigInteger.Parse(key.a), BigInteger.Parse(key.b));
        }

        public static string SerializePrivateKey(BigInteger key, string fileDir = null)
        {
            var opt = new JsonSerializerOptions() {WriteIndented=true};
            string result = JsonSerializer.Serialize(
                new PrivateKeySerialized() {
                    d = key.ToString()
                }, opt);
            
            if(fileDir != null && fileDir.Length > 0)
                SaveToFile(fileDir, result);

            return result;
        }

        public static BigInteger DeserializePrivateKey(string data)
        {
            var key = JsonSerializer.Deserialize<PrivateKeySerialized>(data);
            return BigInteger.Parse(key.d);
        }

        public static string SerializeSignedMessage((BigInteger r, BigInteger s) signature, string message, string fileDir = null)
        {
            var opt = new JsonSerializerOptions() {WriteIndented=true};
            string result = JsonSerializer.Serialize(
                new SignedMessageSerialized(){
                    r = signature.r.ToString(),
                    s = signature.s.ToString(),
                    message = message
                }, opt);
            
            if(fileDir != null && fileDir.Length > 0)
                SaveToFile(fileDir, result);

            return result;
        }

        public static ((BigInteger r, BigInteger s) signature, string message) DeserializeSignedMessage(string data)
        {
            var content = JsonSerializer.Deserialize<SignedMessageSerialized>(data);
            return ((BigInteger.Parse(content.r), BigInteger.Parse(content.s)), content.message);
        }
    }
}