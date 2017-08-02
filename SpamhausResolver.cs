using DnsClient;
using DnsClient.Protocol;
using System;
using System.Collections;
using System.Collections.Generic;
using System.IO;
using System.Linq;
using System.Net;
using System.Net.Http;
using System.Net.Sockets;
using System.Text.RegularExpressions;
using System.Threading.Tasks;
using Tireless.Net.Blocking;

namespace Tireless.Net.Mail
{
    public class SpamhausResolver
    {
        private IPTree blockTree;

        private IPAddress[] spamhausNameserverV4;
        private IPAddress[] spamhausNameserverV6;
        public IPAddress[] SpamhausNameserver
        {
            get { return this.UseIPv6 && this.spamhausNameserverV6.Length > 0 ? this.spamhausNameserverV6 : this.spamhausNameserverV4; }
        }

        /// <summary>
        /// Use ipv6 instead of ipv4.
        /// </summary>
        public Boolean UseIPv6
        {
            get;
            set;
        }

        /// <summary>
        /// Cache all results.
        /// </summary>
        public Boolean UseCache
        {
            get;
            set;
        }

        /// <summary>
        /// No exceptions are thrown.
        /// </summary>
        public Boolean QuietMode
        {
            get;
            set;
        }

        public IPAddress[] NameserverV4
        {
            get;
            set;
        }

        public IPAddress[] NameserverV6
        {
            get;
            set;
        }

        private IPAddress[] Nameserver
        {
            get { return this.UseIPv6 ? this.NameserverV6 : this.NameserverV4; }
        }

        public SpamhausResolver()
        {
            this.blockTree = new IPTree();

            this.NameserverV4 = new IPAddress[] { IPAddress.Parse("8.8.8.8"), IPAddress.Parse("8.8.4.4") };
            this.NameserverV6 = new IPAddress[] { IPAddress.Parse("2001:4860:4860::8888"), IPAddress.Parse("2001:4860:4860::8844") };

            this.spamhausNameserverV4 = new IPAddress[0];
            this.spamhausNameserverV6 = new IPAddress[0];

            this.UseCache = true;
        }

        public async Task InitializeAsync(TimeSpan? timeout = null)
        {
            try
            {
                var lookup = new LookupClient(this.NameserverV4)
                {
                    UseCache = false,
                    Timeout = timeout ?? TimeSpan.FromSeconds(3),
                };

                var nsLookupResult = await lookup.QueryAsync("zen.spamhaus.org", QueryType.NS);
                if (nsLookupResult.Answers.Count > 0)
                {
                    var nsRndResult = nsLookupResult.Answers.ElementAt((int)(DateTime.UtcNow.Ticks % nsLookupResult.Answers.Count));

                    if (nsRndResult is NsRecord nsRecord)
                    {
                        var hostV4List = new List<IPAddress>();
                        var hostV6List = new List<IPAddress>();
                        var hostEntryResult = await lookup.GetHostEntryAsync(nsRecord.NSDName);
                        foreach (var item in hostEntryResult.AddressList)
                        {
                            if (item.AddressFamily == AddressFamily.InterNetwork)
                                hostV4List.Add(item);
                            else if (item.AddressFamily == AddressFamily.InterNetworkV6)
                                hostV6List.Add(item);
                        }
                        this.spamhausNameserverV4 = hostV4List.ToArray();
                        this.spamhausNameserverV6 = hostV6List.ToArray();
                    }
                }
            }
            catch (Exception)
            {
                if (this.QuietMode == false)
                    throw;
            }
        }

        /***********************************************************************/

        public async Task AddUrlAsync(String url)
        {
            try
            {
                using (var httpClient = new HttpClient())
                {
                    using (var httpStream = await httpClient.GetStreamAsync(url))
                    {
                        await this.AddStreamAsync(httpStream);
                    }
                }
            }
            catch (Exception)
            {
                if (this.QuietMode == false)
                    throw;
            }
        }

        public async Task AddFileAsync(String path)
        {
            try
            {
                using (var fileStream = File.OpenRead(path))
                {
                    await this.AddStreamAsync(fileStream);
                }
            }
            catch (Exception)
            {
                if (this.QuietMode == false)
                    throw;
            }
        }

        public async Task AddStreamAsync(Stream baseStream)
        {
            try
            {
                using (var sr = new StreamReader(baseStream))
                {
                    String line;
                    while ((line = await sr.ReadLineAsync()) != null)
                    {
                        if (line.Length == 0 || line[0] == ';')
                            continue;

                        var regex = new Regex(@"^(.*)\/([0-9]+) ; (.*)");
                        var matches = regex.Matches(line);
                        if (matches.Count > 0)
                        {
                            var ip = IPAddress.Parse(matches[0].Groups[1].Value);
                            var netmask = Byte.Parse(matches[0].Groups[2].Value);
                            var ident = matches[0].Groups[3].Value;

                            blockTree.AddNetwork(ip, netmask, ident);
                        }
                    }
                }
            }
            catch (Exception)
            {
                if (this.QuietMode == false)
                    throw;
            }
        }

        public void AddNetwork(IPAddress network, Int32 mask, String identifier = null)
        {
            this.blockTree.AddNetwork(network, mask, identifier);
        }

        public void AddIPAddress(IPAddress client, String identifier = null)
        {
            this.blockTree.AddNetwork(client, client.GetAddressBytes().Length * 8, identifier);
        }

        /***********************************************************************/

        /// <summary>
        /// Calls also InitSpamhausNameservers if not happened before.
        /// </summary>
        /// <param name="client"></param>
        /// <param name="timeout"></param>
        /// <returns></returns>
        public async Task<String> IsBlockedAsync(IPAddress client, TimeSpan? timeout = null)
        {
            try
            {
                if (this.UseCache)
                {
                    String identifier;
                    if ((identifier = this.blockTree.IsBlocked(client)) != null)
                    {
                        if (identifier != SpamhausResult.NL.ToString())
                            return identifier;
                        return null;
                    }
                }

                if (this.SpamhausNameserver.Length == 0)
                    await InitializeAsync(timeout);

                if (this.SpamhausNameserver.Length == 0)
                    return null;

                var lookup = new LookupClient(this.SpamhausNameserver)
                {
                    UseCache = false,
                    Timeout = timeout ?? TimeSpan.FromSeconds(3),
                };

                String reverseIPAddress;
                var ipBytes = new List<Byte>(client.GetAddressBytes()).Reverse<Byte>();
                if (client.AddressFamily == AddressFamily.InterNetwork)
                {
                    reverseIPAddress = String.Join(".", ipBytes);
                }
                else if (client.AddressFamily == AddressFamily.InterNetworkV6)
                {
                    reverseIPAddress = "";
                    foreach (var item in ipBytes.ToArray())
                    {
                        var hex = item.ToString("X2");
                        reverseIPAddress += "." + hex[1] + "." + hex[0];
                    }
                    reverseIPAddress = reverseIPAddress.Substring(1);
                }
                else
                    throw new NotSupportedException();

                var lookupResult = await lookup.QueryAsync(reverseIPAddress.ToLowerInvariant() + ".zen.spamhaus.org", QueryType.A);

                SpamhausResult spamhausResult = SpamhausResult.NL;
                foreach (var item in lookupResult.Answers)
                {
                    if (item is AddressRecord addressRecord)
                    {
                        spamhausResult |= (SpamhausResult)(addressRecord.Address.GetAddressBytes()[3]);
                    }
                }

                if (this.UseCache)
                {
                    this.blockTree.AddIPAddress(client, spamhausResult.ToString());
                }

                return spamhausResult != SpamhausResult.NL ? spamhausResult.ToString() : null;

            }
            catch (Exception)
            {
                if (this.QuietMode == false)
                    throw;
                return null;
            }
        }

        /***********************************************************************/
    }
}
