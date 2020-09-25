using Microsoft.CSharp;
using Microsoft.VisualStudio.TestTools.UnitTesting;
using Newtonsoft.Json;
using System;
using System.CodeDom;
using System.CodeDom.Compiler;
using System.Collections.Concurrent;
using System.Collections.Generic;
using System.Diagnostics;
using System.IO;
using System.Linq;
using System.Linq.Expressions;
using System.Numerics;
using System.Reflection;
using System.Security.Cryptography;
using System.Security.Cryptography.X509Certificates;
using System.Security.Permissions;
using System.Text;
using System.Threading;
using System.Threading.Tasks;

namespace _70_483_Cert
{

    public class ExampleObject
    {

        public List<string> StringList;

        public ExampleObject()
        {
            StringList = new List<string> { "first", "seconds", "third", "fourth", "fifth" };

        }
    }

    [TestClass]
    public class MultiThreadingAndAsyncProcessing
    {
        /// <summary>
        /// Running jobs on a list in parallell. One item is associated with a delay so it will finish last.
        /// </summary>
        [TestMethod]
        public void TestTaskParallell()
        {
            var data = new ExampleObject();
            var processed = new List<string>();
            Parallel.ForEach<string>(data.StringList, (str) =>
            {
                if (str == "third")
                {
                    Thread.Sleep(1000);
                }
                processed.Add(str.Substring(0, 2));
            });
            Parallel.ForEach<string>(processed, (str) => { Console.WriteLine(str); });
            Assert.AreEqual(processed.ToArray()[4], "th");

            var array = data.StringList.ToArray();
            Parallel.For(0, array.Length - 1, (index) => { array[index] = array[index] + "1"; });
            Assert.AreEqual(array[1], "seconds1");
        }

        [TestMethod]
        public void TestPLINQ()
        {
            var data = new ExampleObject();
            var result = from name in data.StringList.AsParallel() where name.Length > 6 select name;
            Assert.AreEqual(result.First(), "seconds");
        }


        /// <summary>
        /// Using async await to have non-blocking code
        /// </summary>
        [TestMethod]
        public void ASyncAwaitTasks()
        {
            var obj1 = new StringBuilder();
            obj1.Append("notasync");
            var myTask = MethodAsync(obj1);
            Assert.AreEqual(obj1.ToString(), "notasync");
            Task.WaitAll(myTask);
            Assert.AreEqual(obj1.ToString(), "notasyncasync");

        }

        private async Task MethodAsync(StringBuilder str)
        {
            await Task.Delay(1000);
            str.Append("async");
        }


        /// <summary>
        /// Shows Task continuation. Notice that we need to wait for contTask or else code may finish before that task is finished.
        /// </summary>
        [TestMethod]
        public void TaskContinuation()
        {
            String status = "";
            Action<Task, object?> finishAction = (task, obj) =>
            {
                Console.WriteLine("Task Finished" + task.Status.ToString());
                status = task.Status.ToString();
            };
            var t = MethodAsync(new StringBuilder());
            var contTask = t.ContinueWith(finishAction, null);
            Task.WaitAll(t, contTask);
            Console.WriteLine(status);
            Assert.AreEqual("RanToCompletion", status);
        }


        /// <summary>
        /// Using a threadpool to give work to be done in separate threads
        /// </summary>
        [TestMethod]
        public void TestThreadPool()
        {
            var data = new BlockingCollection<string>();
            data.Add("first");
            ThreadPool.QueueUserWorkItem(WorkMethod, data);
            Thread.Sleep(1000);
            string str;
            string myout = "";
            while (data.TryTake(out str))
            {
                Console.WriteLine("main" + str);
                myout = str;
            }

            Assert.AreEqual("worker", myout);
        }

        public void WorkMethod(object obj)
        {
            var data = (BlockingCollection<string>)obj;
            data.Add("worker");
            data.CompleteAdding();
            Console.WriteLine("worker" + obj);
        }

    }

    [TestClass]
    public class ManageMultiThreading
    {

        static ReaderWriterLock rwl = new ReaderWriterLock();


        [TestMethod]
        public void SyncResources()
        {
            bool use_lock = true;
            var list = new List<int> { 1 };
            var t1 = new Thread(() => SyncMethods(list, use_lock));
            var t2 = new Thread(() => SyncMethods(list, use_lock));
            t1.Start();
            t2.Start();
            t1.Join();
            t2.Join();

            Assert.AreEqual(4, list.First());
        }

        private void SyncMethods(List<int> list, bool uselock)
        {
            if (uselock)
            {
                rwl.AcquireWriterLock(1000);
            }
            var element = list.First();
            list.RemoveAll((x) => true);
            element = element * 2;
            list.Add(element);
            if (uselock)
            {
                rwl.ReleaseWriterLock();
            }
        }

        [TestMethod]
        public void CancelLongTask()
        {
            var ctoken = new CancellationTokenSource();
            var cancel = ctoken.Token;

            var longtask = Task.Run(async () =>
            {
                for (int i = 0; i < 100; i++)
                {
                    if (cancel.IsCancellationRequested)
                    {
                        Console.WriteLine("abort");
                        break;
                    }
                    Console.WriteLine("ticking away" + i);
                    await Task.Delay(1000);
                }
            });
            Thread.Sleep(2100);
            Console.WriteLine("cancel call");
            ctoken.Cancel();
            Thread.Sleep(2100);
        }

        //Skipped implement thread-safe methods

        //skipped section "Implement program flow"

    }

    [TestClass]
    public class EventsAndCallBacks
    {

        private delegate T BinaryOperator<T>(T in1, T in2) where T : IComparable;
        private event BinaryOperator<int> ScienceEvent;

        [TestMethod]
        public void EventHandlers()
        {
            ScienceEvent += (x, y) => { Console.WriteLine("Added:" + (x + y)); return x + y; };
            ScienceEvent += delegate (int x, int y) { Console.WriteLine("Subtracted:" + (x - y)); return x - y; };

            var a = ScienceEvent(5, 2);
            
        }

    }

    [TestClass]
    public class ExceptionHandling
    {
        [TestMethod]
        public void AggregateExceptionHandling()
        {
            try
            {
                var t = Task.Run(() =>
                {
                    var y = 0;
                    var x = 23 / y;
                });

                var t2 = Task.Run(() =>
                {
                    var y = 0;
                    var x = 23 / y;
                });

                Task.WaitAll(t, t2);

            }
            catch (AggregateException ex)
            {
                foreach (var inner in ex.InnerExceptions)
                {
                    Console.WriteLine(inner.Message);
                }
            }
        }
    }

    public static class ExtensionMethods
    {
        public static string Duplicate(this string inst)
        {
            return inst + inst;
        }
    }

    [TestClass]
    public class TypeTest
    {
        private enum MyEnum { KALLE, OLLE, STINE };

        private struct MyStruct
        {
            public int number;
            public string name;

            public string MyMethod()
            {
                return name + "-string";
            }
        }

        [TestMethod]
        public void TypeCreation()
        {
            var Name = MyEnum.KALLE;
            var Struct = new MyStruct { name = "olle" };
            var output = Struct.MyMethod();
            Console.WriteLine(output);
            Assert.AreEqual("olle-string", output);
        }

        [TestMethod]
        public void ExtensionMethod()
        {
            string s = "olle";
            Assert.AreEqual("olleolle", s.Duplicate());
        }

        public void MethodWithParams(int first, string name, int test = 10)
        {

        }

        [TestMethod]
        public void OptionalAndNamedParams()
        {
            MethodWithParams(name: "okok", first: 1);

        }

    }

    //Reflection etc
    public class AuthorAttribute : System.Attribute
    {
        private string name { get; set; }
        public double version;

        public AuthorAttribute() : this("Kalle") { }



        public AuthorAttribute(string name)
        {
            this.name = name;
            version = 1.0;
        }



        public override string ToString()
        {
            return base.ToString() + " " + name + version;
        }
    }

    [Author("Tony", version = 1.1)]
    [TestClass]
    public class ReflectionTest
    {
        [TestMethod]
        public void TestReadClassAttribute()
        {
            AuthorAttribute author = null;
            System.Attribute[] attrs = System.Attribute.GetCustomAttributes(typeof(ReflectionTest));
            foreach (var att in attrs)
            {
                if (att is AuthorAttribute)
                {
                    author = (AuthorAttribute)att;
                    Console.WriteLine(author);
                }
            }

            var fields = author.GetType().GetFields(BindingFlags.Instance | BindingFlags.NonPublic | BindingFlags.Public);
            foreach (var f in fields)
            {
                Console.WriteLine(f.Name);
            }
            Assert.IsNotNull(author);
        }


        //Generates a HelloWorld program
        [TestMethod]
        public void TestCodeDOM()
        {
            CodeCompileUnit compileUnit = new CodeCompileUnit();
            CodeNamespace myNamespace = new CodeNamespace("MyNamespace");
            myNamespace.Imports.Add(new CodeNamespaceImport("System"));
            CodeTypeDeclaration myClass = new CodeTypeDeclaration("MyClass");
            CodeEntryPointMethod start = new CodeEntryPointMethod();
            CodeMethodInvokeExpression cs1 = new CodeMethodInvokeExpression(
            new CodeTypeReferenceExpression("Console"), "WriteLine", new CodePrimitiveExpression("Hello World!"));


            compileUnit.Namespaces.Add(myNamespace);
            myNamespace.Types.Add(myClass);
            myClass.Members.Add(start);
            start.Statements.Add(cs1);

            CSharpCodeProvider provider = new CSharpCodeProvider();
            using (StreamWriter sw = new StreamWriter("HelloWorld.cs", false))
            {
                IndentedTextWriter tw = new IndentedTextWriter(sw, " ");
                provider.GenerateCodeFromCompileUnit(compileUnit, tw,
                new CodeGeneratorOptions());
                tw.Close();
            }

        }


        [TestMethod]
        public void TestExpressionTree()
        {

            // Creating a parameter expression.  
            ParameterExpression value = Expression.Parameter(typeof(int), "value");

            // Creating an expression to hold a local variable.
            ParameterExpression result = Expression.Parameter(typeof(int), "result");

            // Creating a label to jump to from a loop.  
            LabelTarget label = Expression.Label(typeof(int));

            // Creating a method body.  
            BlockExpression block = Expression.Block(
                // Adding a local variable.  
                new[] { result },
                // Assigning a constant to a local variable: result = 1  
                Expression.Assign(result, Expression.Constant(1)),
                    // Adding a loop.  
                    Expression.Loop(
                       // Adding a conditional block into the loop.  
                       Expression.IfThenElse(
                           // Condition: value > 1  
                           Expression.GreaterThan(value, Expression.Constant(1)),
                           // If true: result *= value --  
                           Expression.MultiplyAssign(result,
                               Expression.PostDecrementAssign(value)),
                           // If false, exit the loop and go to the label.  
                           Expression.Break(label, result)
                       ),
                   // Label to jump to.  
                   label
                )
            );

            var factorial = Expression.Lambda<Func<int, int>>(block, value).Compile();
            Console.WriteLine(factorial(5));
        }

        [TestMethod]
        public void AssemblyTest()
        {
            Assembly asm = typeof(AuthorAttribute).Assembly;

            foreach (var type in asm.DefinedTypes)
            {
                Console.WriteLine(type.FullName);
            }

            var inst = asm.CreateInstance("_70_483_Cert.AuthorAttribute");

            Console.WriteLine(inst);

        }

    }

    [TestClass]
    public class StringManipulation
    {

        [TestMethod]
        public void StringWriterTest()
        {
            string lineString = "oololeoeloe\nool000oleoeloe\noolol1212eoeloe\noolo3434leoeloe\n";
            var strw = new StringReader(lineString);
            var strout = "";
            while (true)
            {
                var line = strw.ReadLine();


                if (line == null)
                {
                    break;
                }
                else
                {
                    strout = strout + line + "-";
                }
            }
            Console.WriteLine(strout);

            var writer = new StringWriter();
            writer.WriteLine("kalle");
            writer.Write('h');
            writer.Write((char)222);
            Console.WriteLine(writer.ToString());
        }


    }

    public class Dog
    {
        public string name { get; set; }
        public Dog()
        {
            name = "fido";
        }
    }

    [TestClass]
    public class DebugAndImplementSecurity
    {
        [TestMethod]
        public void TestJsonSerializer()
        {
            var d = new Dog();
            TextWriter strw = new StringWriter();

            strw.Write(System.Text.Json.JsonSerializer.Serialize(d));
            Console.WriteLine(strw.ToString());

            System.Text.Json.JsonSerializer.Deserialize<Dog>(strw.ToString());

        }

        [TestMethod]
        public void SymmetricEncryptionTesting()
        {
            var transform = new AesManaged();
            byte[] bytes = Encrypt(transform, "My secret");
            string decrypt = Decrypt(transform, bytes);
            Console.WriteLine(decrypt);
        }

        static byte[] Encrypt(SymmetricAlgorithm aesAlg, string plainText)
        {
            ICryptoTransform encryptor = aesAlg.CreateEncryptor(aesAlg.Key, aesAlg.IV);
            using (MemoryStream msEncrypt = new MemoryStream())
            {
                using (CryptoStream csEncrypt =
                new CryptoStream(msEncrypt, encryptor, CryptoStreamMode.Write))
                {
                    using (StreamWriter swEncrypt = new StreamWriter(csEncrypt))
                    {
                        swEncrypt.Write(plainText);
                    }
                    return msEncrypt.ToArray();
                }
            }
        }

        static string Decrypt(SymmetricAlgorithm aesAlg, byte[] cipherText)
        {
            ICryptoTransform decryptor = aesAlg.CreateDecryptor(aesAlg.Key, aesAlg.IV);
            using (MemoryStream msDecrypt = new MemoryStream(cipherText))
            {
                using (CryptoStream csDecrypt =
                new CryptoStream(msDecrypt, decryptor, CryptoStreamMode.Read))
                {
                    using (StreamReader srDecrypt = new StreamReader(csDecrypt))
                    {
                        return srDecrypt.ReadToEnd();
                    }
                }
            }
        }

        [TestMethod]
        public void AsymmetricEncryptionTesting()
        {
            UnicodeEncoding ByteConverter = new UnicodeEncoding();

            var rsaProv = new RSACryptoServiceProvider();
            rsaProv.ToXmlString(true);
            rsaProv.Encrypt(Encoding.ASCII.GetBytes("olle"), false);


            RSACryptoServiceProvider rsa = new RSACryptoServiceProvider();
            string publicKeyXML = rsa.ToXmlString(false);
            string privateKeyXML = rsa.ToXmlString(true);

            byte[] dataToEncrypt = Encoding.ASCII.GetBytes("My Secret Data!");
            byte[] encryptedData;
            using (RSACryptoServiceProvider RSA = new RSACryptoServiceProvider())
            {
                RSA.FromXmlString(publicKeyXML);
                encryptedData = RSA.Encrypt(dataToEncrypt, false);
            }
            byte[] decryptedData;
            using (RSACryptoServiceProvider RSA = new RSACryptoServiceProvider())
            {
                RSA.FromXmlString(privateKeyXML);
                decryptedData = RSA.Decrypt(encryptedData, false);
                
            }
            string decryptedString = Encoding.ASCII.GetString(decryptedData);
            Console.WriteLine(decryptedString); // Displays: My Secret Data!
            Assert.AreEqual("My Secret Data!", decryptedString);
        }

        [TestMethod]
        public void HashingTest()
        {
            var sha = SHA256.Create();
            byte[] hash = sha.ComputeHash(Encoding.ASCII.GetBytes("Tonyb"));
            var thehash = Encoding.UTF8.GetString(hash);
            var str = BitConverter.ToString(hash);
            Console.WriteLine($"my hash: {str:X}  \nLength"+hash.Length);

        }

        [TestMethod]
        public void CertificateTest()
        {
            string textToSign = "Test paragraph";
            byte[] signature = Sign(textToSign, "cn = WouterDeKort");
            // Uncomment this line to make the verification step fail
            // signature[0] = 0;
            Console.WriteLine(Verify(textToSign, signature));

        }

        static byte[] Sign(string text, string certSubject)
        {
            X509Certificate2 cert = GetCertificate();
            var csp = (RSACryptoServiceProvider)cert.PrivateKey;
            byte[] hash = HashData(text);
            return csp.SignHash(hash, CryptoConfig.MapNameToOID("SHA1"));
        }
        static bool Verify(string text, byte[] signature)
        {
            X509Certificate2 cert = GetCertificate();
            var csp = (RSACryptoServiceProvider)cert.PublicKey.Key;
            byte[] hash = HashData(text);
            return csp.VerifyHash(hash,
            CryptoConfig.MapNameToOID("SHA1"),
            signature);
        }
        private static byte[] HashData(string text)
        {
            HashAlgorithm hashAlgorithm = new SHA1Managed();
            UnicodeEncoding encoding = new UnicodeEncoding();
            byte[] data = encoding.GetBytes(text);
            byte[] hash = hashAlgorithm.ComputeHash(data);
            return hash;
        }
        private static X509Certificate2 GetCertificate()
        {
            X509Store my = new X509Store("testCertStore",
            StoreLocation.CurrentUser);
            my.Open(OpenFlags.ReadOnly);
            var certificate = my.Certificates[0];
            return certificate;
        }


 
    }

    [TestClass]
    public class DiagnosticsDebug
    {
        const int numberOfIterations = 10000;

        [TestMethod]
        public void TestStopStartWatch()
        {
     
            
                Stopwatch sw = new Stopwatch();
                sw.Start();
                Algorithm1();
                sw.Stop();
                Console.WriteLine(sw.Elapsed);
                sw.Reset();
                sw.Start();
                Algorithm2();
                sw.Stop();
                Console.WriteLine(sw.Elapsed);
        }
        private static void Algorithm2()
        {
            string result = "";
            for (int x = 0; x < numberOfIterations; x++)
            {
                result += 'a';
            }
        }
        private static void Algorithm1()
        {
            StringBuilder sb = new StringBuilder();
            for (int x = 0; x < numberOfIterations; x++)
            {
                sb.Append('a');
            }
            string result = sb.ToString();
        }
        

    }


    
}
