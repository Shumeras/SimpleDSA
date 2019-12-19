using System;
using System.Numerics;
using System.Text.Json;
using System.Text;

namespace DSA
{
    class Program
    {
      
        static void Main(string[] args)
        {

            if(args.Length == 0 || (args[0].ToLower() != "generate" && args[0].ToLower() != "sign" && args[0].ToLower() != "validate"))
            {
                System.Console.WriteLine("Try: generate | sign | validate");
                return;
            } 
            
            if(args[0].ToLower() == "generate")
            {
                int N = 1024;
                int L = 160;
                string saveFileDir = "";

                for(int i = 0; i < args.Length; i++)
                {
                    if(i == 0) continue;

                    if(args[i].ToLower().Contains("-n"))
                    {
                        i++;
                        N = int.Parse(args[i]);
                    }
                    else if(args[i].ToLower().Contains("-l"))
                    {
                        i++;
                        L = int.Parse(args[i]);
                    }
                    else
                    {
                        saveFileDir = args[i]; 
                    }
                }

                var(publicKey, privateKey) = DSA.generateKeys(N/8, L/8);
                
                if(saveFileDir.Length > 0)
                {
                    Utilities.SerializePublicKey(publicKey, saveFileDir+"_public.json");
                    Utilities.SerializePrivateKey(privateKey, saveFileDir+"_private.json");
                }
                else
                {
                    System.Console.WriteLine("Public Key:");
                    System.Console.WriteLine(Utilities.SerializePublicKey(publicKey));
                    System.Console.WriteLine("Private Key:");
                    System.Console.WriteLine(Utilities.SerializePrivateKey(privateKey));
                }

            }
            else if(args[0].ToLower() == "sign")
            {
                if(args.Length < 4)
                {
                    System.Console.WriteLine("sign <publicKeyFile> <privateKeyFile> <message> | <publicKeyFile> <privateKeyFile> <message> <signedFileSaveDir>");
                    return;
                }

                string  publicKeyFile = "", 
                        privateKeyFile = "",
                        message = "", 
                        signedMessageFile = "";

                for(int i = 1; i < args.Length; i++)
                {
                    if(publicKeyFile == "")
                        publicKeyFile = args[i];
                    else if(privateKeyFile == "")
                        privateKeyFile = args[i];
                    else if(message == "")
                        message = args[i];
                    else if(signedMessageFile == "")
                        signedMessageFile = args[i];
                    else
                    {
                        System.Console.WriteLine("Supplied to many arguments");
                        return;
                    } 
                }

                if(publicKeyFile == "" || privateKeyFile == "" || message == "")
                    {
                        System.Console.WriteLine("Missing arguments");
                        return;
                    }    

                    var publicKey = Utilities.DeserializePublicKey(Utilities.LoadFromFile(publicKeyFile));
                    var privateKey = Utilities.DeserializePrivateKey(Utilities.LoadFromFile(privateKeyFile));
                    var signature = DSA.sign(publicKey, privateKey, Encoding.UTF8.GetBytes(message));
                
                    if(signedMessageFile == "")
                        System.Console.WriteLine(Utilities.SerializeSignedMessage(signature, message));
                    else
                        Utilities.SerializeSignedMessage(signature, message, signedMessageFile+".json");

            }
            else if(args[0].ToLower() == "validate")
            {
                if(args.Length < 3)
                {
                    System.Console.WriteLine("validate <signedMessageFile> <publicKeyFile>");
                    return;
                }

                string  messageFile = "",
                        publicKeyFile = "";

                for(var i = 1; i < args.Length; i++ )
                {
                    if(messageFile == "")
                        messageFile = args[i];
                    else if(publicKeyFile == "")
                        publicKeyFile = args[i];
                }

                var publicKey = Utilities.DeserializePublicKey(Utilities.LoadFromFile(publicKeyFile));
                var (signature, message) = Utilities.DeserializeSignedMessage(Utilities.LoadFromFile(messageFile));

                if(DSA.validate(publicKey, signature, Encoding.UTF8.GetBytes(message)))
                    System.Console.WriteLine("Signature is VALID!");
                else
                    System.Console.WriteLine("Signature is INVALID!");

            }
            else{
                System.Console.WriteLine("Unknown command");
            }

            

        }

        
    }
}
