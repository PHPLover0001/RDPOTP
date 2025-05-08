using System.Net;

namespace RdpOtp
{
    //연결정보 클레스
    public class ConnectionInfo
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
}
