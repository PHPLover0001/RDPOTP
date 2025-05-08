using System.Net;
using System.Net.Sockets;
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

        static List<ConnectionInfo> connectionList = new List<ConnectionInfo>();

        static async Task Main()
        {
            //기본설정 로드
            LoadConfiguration();

            Console.WriteLine($"RDP 서버: {rdpHost}:{rdpPort}");
            Console.WriteLine($"프록시 포트: PORT : {proxyListenPort}");
            Console.WriteLine($"웹서버: {webHost}:{webPort}");

            Console.WriteLine("");
            Console.WriteLine("");

            var listener = new TcpListener(IPAddress.Any, proxyListenPort);
            listener.Start();
            Console.WriteLine("RDP 프록시 서버 실행 중 (포트 3390)...");

            _ = Task.Run(() => RunWebServer());
            Console.WriteLine($"웹서버 실행 중: http://{((webHost == "localhost") ? "127.0.0.1" : webHost)}:{webPort}/");


            while (true)
            {
                var client = await listener.AcceptTcpClientAsync();
                _ = Task.Run(() => HandleClient(client));
            }
        }

        static async Task RunWebServer()
        {
            HttpListener http = new HttpListener();
            http.Prefixes.Add($"http://{webHost}:{webPort}/");
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

            // 커넥션 등록
            ConnectionInfo connectionInfo = new ConnectionInfo((IPEndPoint)client.Client.RemoteEndPoint);

            // connectionList에 등록
            updateTime(connectionInfo);

            byte[] buffer = new byte[4096];
            int bytesRead = await clientStream.ReadAsync(buffer, 0, buffer.Length);

            // Negotiation Response 생성 
            byte[] negotiationResponsePartial = new byte[]
            {
            0x03, 0x00, 0x00, 0x0b, // TPKT header
            0x06, 0xe0, 0x00, 0x00, 0x00, 0x00, 0x00, // X.224 partial
            };

            await clientStream.WriteAsync(negotiationResponsePartial, 0, negotiationResponsePartial.Length);
            await clientStream.FlushAsync();

            Console.WriteLine("Negotiation Response 일부 전송 - 인증 대기 중...");

            DateTime now = DateTime.UtcNow;

            // 인증후 30초내 재연결시 인증없이 통과
            var item = connectionList.FirstOrDefault(c => c.EndPoint.Address.ToString() == connectionInfo.EndPoint.Address.ToString());
            if (item!=null && item.state == 1 && (now - item.time).TotalSeconds <= 60)
            {
                updateTime(connectionInfo);
            }
            else
            {
                // 인증 대기
                for (int i = 0; i < 60; i++)
                {
                    if (CheckOtpAuth(connectionInfo)) break;
                    await Task.Delay(1000);
                    Console.WriteLine(i);
                }

                //연결 중단
                if (!CheckOtpAuth(connectionInfo))
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
                // RDP 서버에 연결
                var rdpServer = new TcpClient(rdpHost, rdpPort);
                using (rdpServer)
                using (client)
                using (var rdpStream = rdpServer.GetStream())
                {
                    // 초기 Negotiation Request → RDP 서버로 전달
                    await rdpStream.WriteAsync(buffer, 0, bytesRead);
                    await rdpStream.FlushAsync();

                    // 양방향 데이터 중계 시작
                    var toServer = clientStream.CopyToAsync(rdpStream);
                    var toClient = rdpStream.CopyToAsync(clientStream);

                    Console.WriteLine("RDP 데이터 중계 시작...");
                    await Task.WhenAny(toServer, toClient);  // 하나라도 끊기면 빠져나옴

                    // 연결 종료 감지 시 모든 작업 완료 대기
                    await Task.WhenAll(toServer, toClient);
                }
            }
            catch (Exception ex)
            {
                Console.WriteLine("[*] 연결 종료됨.");
                updateTime(connectionInfo);
            }
            finally
            {
                Console.WriteLine("[*] 연결 종료됨.");
                updateTime(connectionInfo);
            }
        }

        //연결 허용 체크
        static bool CheckOtpAuth(ConnectionInfo connectionInfo)
        {
            if (connectionInfo.state == 1)
                return true;
            return false;
        }

        //appsettings.json로드
        static void LoadConfiguration()
        {
            config = new ConfigurationBuilder()
                .AddJsonFile("appsettings.json", optional: false, reloadOnChange: true)
                .Build();
            //Rdp설정
            rdpHost = config["RdpServer:Host"] ?? "127.0.0.1";
            rdpPort = int.Parse(config["RdpServer:Port"] ?? "3389");

            //프록시 포트 설정
            proxyListenPort = int.Parse(config["Proxy:ListenPort"] ?? "3390");

            //웹서버 설정
            webHost = config["Web:ip"] ?? "localhost";
            webPort = int.Parse(config["Web:Port"] ?? "8080");
        }

        //접속시간 갱신
        static void updateTime(ConnectionInfo conn,int addTime = 0)
        {
            conn.time = DateTime.UtcNow;
            //리스트에 없으면 추가
            var item = connectionList.FirstOrDefault(c => c.EndPoint.Address.ToString() == conn.EndPoint.Address.ToString());
            if (item == null)
            {
                connectionList.Add(conn);
                //connectionList가 10개가 넘으면 마지막 10개만 남기기
                if (connectionList.Count > 10)
                {
                    connectionList.RemoveRange(0, connectionList.Count - 10);
                }
            }
            else
            {
                //리스트에 있으면 최하단으로
                connectionList.Remove(item);
                connectionList.Add(item);
            }
        }
    }
}