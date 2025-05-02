using System.Net.Sockets;
using System.Net;
using Microsoft.Extensions.Configuration;
using Microsoft.Extensions.Configuration.Json;
using Microsoft.Extensions.Configuration.EnvironmentVariables;
using System.Text;

namespace RdpOtp
{
    internal class Program
    {
        static string rdpHost;
        static int rdpPort;
        static int proxyListenPort;

        static string webHost;
        static int webPort;

        static IConfiguration config;

        //인증된 마지막 IP 및 시각
        static IPAddress? lastAuthIp = null;
        static DateTime lastAuthTime = DateTime.MinValue;

        class ConnectionInfo
        {
            private static int _globalNum = 0;
            public int num { get; private set; }
            public IPEndPoint EndPoint { get; set; }
            public int state { get; set; }
            public DateTime time { get; set; }

            public ConnectionInfo(IPEndPoint endPoint)
            {
                this.num = ++_globalNum; // Increment and assign unique num
                this.EndPoint = new IPEndPoint(endPoint.Address, endPoint.Port);
                this.state = 0;
                this.time = DateTime.UtcNow;
            }
        }

        static List<ConnectionInfo> connectionList = new List<ConnectionInfo>();

        static async Task Main()
        {
            // Load config from appsettings.json
            config = new ConfigurationBuilder()
                .AddJsonFile("appsettings.json", optional: false, reloadOnChange: true)
                .Build();

            // Read values
            rdpHost = config["RdpServer:Host"] ?? "127.0.0.1";
            rdpPort = int.Parse(config["RdpServer:Port"] ?? "3391");

            proxyListenPort = int.Parse(config["Proxy:ListenPort"] ?? "3390");

            // 웹서버 설정 읽기
            webHost = config["Web:ip"] ?? "+";
            webPort = int.Parse(config["Web:Port"] ?? "8080");

            Console.WriteLine($"RDP 서버: {rdpHost}:{rdpPort}");
            Console.WriteLine($"프록시 포트: PORT : {proxyListenPort}");
            Console.WriteLine($"웹서버: {webHost}:{webPort}");

            Console.WriteLine("");
            Console.WriteLine("");

            var listener = new TcpListener(IPAddress.Any, proxyListenPort);
            listener.Start();
            Console.WriteLine("RDP 프록시 서버 실행 중 (포트 3390)...");
            Console.WriteLine($"웹서버 실행 중: http://{((webHost == "+") ? "localhost" : webHost)}:{webPort}/");

            _ = Task.Run(() => RunWebServer());


            while (true)
            {
                var client = await listener.AcceptTcpClientAsync();
                _ = Task.Run(() => HandleClient(client));
            }
        }

        static async Task RunWebServer()
        {
            HttpListener http = new HttpListener();
            http.Prefixes.Add($"http://+:{webPort}/");
            http.Start();

            while (true)
            {
                var context = await http.GetContextAsync();
                var req = context.Request;
                var res = context.Response;

                if (req.HttpMethod == "GET")
                {

                    var query = System.Web.HttpUtility.ParseQueryString(req.Url.Query);

                    int num = int.TryParse(query["num"], out var parsedNum) ? parsedNum : -1;
                    int pass = int.TryParse(query["pass"], out var parsedPass) ? parsedPass : -1;
                    Console.WriteLine($"num: {num}, pass: {pass}");

                    var item = connectionList.FirstOrDefault(c => c.num == num);
                    if (item != null)
                    {
                        item.state = pass;
                    }



                    string html = "{";
                    foreach (var ip in connectionList)
                    {
                        string json =
                            $"{{\n" +
                            $"  \"num\": \"{ip.num}\",\n" +
                            $"  \"ip\": \"{ip.EndPoint.Address}\",\n" +
                            $"  \"port\": {ip.EndPoint.Port}\n" +
                            $"  \"state\": {ip.state}\n" +
                            $"  \"time\": {ip.time}\n" +
                            $"}},";

                        html += json;
                    }
                    html += "}";

                    byte[] buffer = Encoding.UTF8.GetBytes(html);
                    res.ContentType = "text/html";
                    res.ContentLength64 = buffer.Length;
                    await res.OutputStream.WriteAsync(buffer, 0, buffer.Length);
                }
                else
                {
                    res.StatusCode = 404;
                }

                res.OutputStream.Close();
            }
        }


        static async Task HandleClient(TcpClient client)
        {
            var clientStream = client.GetStream();
            IPAddress ip = ((IPEndPoint)client.Client.RemoteEndPoint).Address;
            int port = ((IPEndPoint)client.Client.RemoteEndPoint).Port;
            Console.WriteLine($"클라이언트 접속: {ip}");

            ConnectionInfo connectionInfo = new ConnectionInfo((IPEndPoint)client.Client.RemoteEndPoint);
            connectionList.Add(connectionInfo);
            //connectionList가 10개가 넘으면 최근 10개만 남기기
            if (connectionList.Count > 10)
            {
                connectionList.RemoveRange(0, connectionList.Count - 10);
            }

            byte[] buffer = new byte[4096];
            int bytesRead = await clientStream.ReadAsync(buffer, 0, buffer.Length);

            // 시간 끌기용으로 일부 Negotiation Response 전송
            byte[] negotiationResponsePartial = new byte[]
            {
            0x03, 0x00, 0x00, 0x0b, // TPKT header
            0x06, 0xe0, 0x00, 0x00, 0x00, 0x00, 0x00 // X.224 partial
            };

            await clientStream.WriteAsync(negotiationResponsePartial, 0, negotiationResponsePartial.Length);
            await clientStream.FlushAsync();

            Console.WriteLine("Negotiation Response 일부 전송 - 인증 대기 중...");

            DateTime now = DateTime.UtcNow;

            if(lastAuthIp != null && lastAuthIp.Equals(ip) && (now - lastAuthTime).TotalSeconds <= 60)
            {
                connectionInfo.state = 1;
            }
            else
            {
                // 인증 대기
                for (int i = 0; i < 15; i++)
                {
                    if (await CheckOtpAuth(connectionInfo)) break;
                    await Task.Delay(1000);
                    Console.WriteLine(i);
                }

                //연결 중단
                if (!await CheckOtpAuth(connectionInfo))
                {
                    Console.WriteLine("\n[!] 인증 실패. 연결 종료.");
                    client.Close();
                    return;
                }
            }

            Console.WriteLine("\n[+] 인증 성공! 내부 RDP 서버에 연결 중...");

            now = DateTime.UtcNow;
            lastAuthIp = ip;
            lastAuthTime = now;

            try
            {
                //RDP 서버에 연결
                var rdpServer = new TcpClient(rdpHost, rdpPort); // ← RDP 서버 IP
                using (rdpServer)
                {
                    var rdpStream = rdpServer.GetStream();

                    // 초기 Negotiation Request → RDP 서버로 전달
                    await rdpStream.WriteAsync(buffer, 0, bytesRead);
                    await rdpStream.FlushAsync();

                    // 양방향 데이터 중계 시작
                    var toServer = clientStream.CopyToAsync(rdpStream);
                    var toClient = rdpStream.CopyToAsync(clientStream);

                    Console.WriteLine("RDP 데이터 중계 시작...");
                    await Task.WhenAny(toServer, toClient);
                }
            }
            catch (Exception ex)
            {
                Console.WriteLine($"[!] RDP 서버 연결 실패: {ex.Message}");
            }
        }

        static async Task<bool> CheckOtpAuth(ConnectionInfo connectionInfo)
        {
            if(connectionInfo.state == 1)
                return true;
            return false;
        }
    }
}
