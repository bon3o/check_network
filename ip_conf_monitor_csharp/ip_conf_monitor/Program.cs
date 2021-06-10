using System;
using System.IO;
using System.Net;
using System.Linq;
using System.Text;
using Newtonsoft.Json;
using System.Management;
using System.Net.Sockets;
using System.Configuration;
using Newtonsoft.Json.Linq;
using System.Collections.Generic;
using System.Net.NetworkInformation;
using System.Collections.Specialized;


namespace ip_conf_monitor
{
	class Program
	{
		static NameValueCollection errorMessages = ConfigurationManager.GetSection("errorConfig") as NameValueCollection;

		static int Main(string[] args)
		{
			bool gotDns = false;
			bool goOn = true;
			bool needRoutes = false;
			string nicName = "";
			List<string> errors = new List<string>();
			List<IPAddress> correctDns = new List<IPAddress>();
			IPAddress subnetMask = IPAddress.Parse("0.0.0.0");
			IPAddress defaultGateway = IPAddress.Parse("0.0.0.0");
			IPAddress hostIP = IPAddress.Parse("0.0.0.0");
			List<string> dnsWords = new List<string>() { "primary", "secondary" };
			NameValueCollection contourConfig = ConfigurationManager.GetSection("contourConfig") as NameValueCollection;
			NameValueCollection routesConfig = ConfigurationManager.GetSection("routesConfig") as NameValueCollection;
			int nicIndex = 0;
			string hostName = Dns.GetHostName().Split('.')[0].ToUpper();
			string hostNamePrefix = hostName.Split('-')[0];
			string redisHost = get_zabbbix_address();
			string insightUri = String.Format("http://{0}/3/GET/insight", redisHost);
			string dnsUri = String.Format("http://{0}/6/GET/", redisHost);
			string redisKeyPrefix = "TEMPLATE_APP_IP_CONFIG_MONITOR_";
			string redisInsightData = Get_Data_From_Redis(insightUri);

			try
			{
				List<string> contours = Get_Contours(redisInsightData, hostName);
				hostNamePrefix = Get_Correct_Prefix(hostNamePrefix, contours, contourConfig);
			}
			catch 
			{
				errors.Add(string.Format(errorMessages["contourRedis"], insightUri));
				goOn = false;
			}
			
			string dnsFullUri = string.Format("{0}{1}{2}", dnsUri, redisKeyPrefix, hostNamePrefix);

			if (args.Length != 2)
			{
				Console.WriteLine(errorMessages["args"]); // Переделать под джейсон
				return 0;
			}
			if (args[0] == "True")
			{
				Console.WriteLine(errorMessages["bypass"]); // Переделать под джейсон
				return 0;
			}
			if (args[1] != "None")
			{
				foreach (string dnsServer in args[1].Split(','))
				{
					IPAddress address = IPAddress.Parse(dnsServer);
					correctDns.Add(address);
				}
				gotDns = true;
			}
			else
			{
				correctDns = Get_Correct_Dns(dnsFullUri, hostNamePrefix);
				if (correctDns.Count > 0)
				{
					gotDns = true;
				}
			}

			if (gotDns & goOn)
			{
				/*
				 Gather all information on configured interface(DNS and Gateway values do exist)
				 */
				NetworkInterface[] allNics = NetworkInterface.GetAllNetworkInterfaces();
				foreach (NetworkInterface nic in allNics)

				{
					List<IPAddress> currentDns = new List<IPAddress>();
					nicName = nic.Name;
					if (nic.NetworkInterfaceType == NetworkInterfaceType.Loopback | nic.OperationalStatus != OperationalStatus.Up)
					{
						continue;
					}
					IPInterfaceProperties nicProps = nic.GetIPProperties();
					nicIndex = nicProps.GetIPv4Properties().Index;
					if (nicProps.DnsAddresses.Count > 0 & nicProps.GatewayAddresses.Count > 0)
					{
						foreach (IPAddress dnsAddr in nicProps.DnsAddresses)
						{
							currentDns.Add(dnsAddr);
						}
						var defaultGateways = nicProps.GatewayAddresses;
						foreach (var gwIP in defaultGateways) //Sometimes, first value is '0.0.0.0'. Windows...
						{
							if (!gwIP.Address.Equals(IPAddress.Parse("0.0.0.0")))
							{
								defaultGateway = gwIP.Address;
								break;
							}
						}
						foreach (UnicastIPAddressInformation unicastIPAddressInformation in nic.GetIPProperties().UnicastAddresses)
						{
							if (unicastIPAddressInformation.Address.AddressFamily == AddressFamily.InterNetwork)
							{
								hostIP = unicastIPAddressInformation.Address;
								subnetMask = unicastIPAddressInformation.IPv4Mask;
								bool oneNetwork = Check_One_Network(hostIP.ToString(), defaultGateway.ToString(), subnetMask.ToString());
								if (!oneNetwork)
								{
									errors.Add(string.Format(errorMessages["oneNetwork"], hostIP, nicName, defaultGateway, subnetMask));
								}
							}
						}

						/*
						Check configuration of DNS servers based on data from redis or from command line argument.  
						 */
						for (int i = 0; i < correctDns.Count; i++)
						{
							try
							{
								if (!correctDns[i].Equals(currentDns[i]))
								{
									errors.Add(string.Format(errorMessages["dnsConfig"], dnsWords[i], nicName, correctDns[i], currentDns[i]));
								}
							}
							catch
							{
								errors.Add(string.Format(errorMessages["dnsConfig"], dnsWords[i], nicName, correctDns[i], "None"));
							}
						}
						if (currentDns.Count > 2)
						{
							errors.Add(string.Format(errorMessages["dnsCount"], nicName, currentDns.Count));
						}
						/*
						Check if default`s gateway last octet equals '1'. Otherwise check if there are default routes from config available.
						 */
						if (defaultGateway.GetAddressBytes()[3] != 1 & !needRoutes)
						{
							var routesConfigWriteableCopy = new NameValueCollection(routesConfig);
							needRoutes = true;
							string Namespace = @"root\cimv2";
							string routeQuery = "SELECT Destination, Mask FROM Win32_IP4PersistedRouteTable";
							ManagementObjectSearcher searcher = new ManagementObjectSearcher(Namespace, routeQuery);
							ManagementObjectCollection routes = searcher.Get();
							foreach (ManagementObject route in routes)
							{
								string destination = "";
								string mask = "";
								foreach (PropertyData prop in route.Properties)
								{
									if (prop.Name == "Destination")
									{
										destination = prop.Value.ToString();
									}
									else if (prop.Name == "Mask")
									{
										mask = prop.Value.ToString();
									}
								}
								if (routesConfigWriteableCopy.AllKeys.Contains(destination))
								{
									if (routesConfigWriteableCopy[destination] == mask)
									{
										routesConfigWriteableCopy.Remove(destination);
									}
								}
							}
							if (routesConfigWriteableCopy.Count > 0)
							{
								foreach (string key in routesConfigWriteableCopy.AllKeys)
								{
									errors.Add(string.Format(errorMessages["routes"], defaultGateway, nicName, key, routesConfigWriteableCopy[key]));
								}
							}

						}

					}
				}
			}
			else
			{
				if (goOn)
				{
					errors.Add(string.Format(errorMessages["dnsRedis"], dnsFullUri, hostNamePrefix));
				}
			}

			if (errors.Count > 0)
			{
				Console.WriteLine(String.Join("\n", errors));
			}
			else
			{
				Console.WriteLine(0);
			}
			return 0;
		}

		static List<IPAddress> Get_Correct_Dns(string dnsUri, string hostNamePrefix)
		{
			List<IPAddress> dnsData = new List<IPAddress>();
			try
			{
				string redisRawData = Get_Data_From_Redis(dnsUri);
				dynamic jsonObj = JsonConvert.DeserializeObject(redisRawData);
				string getResult = jsonObj.GET;
				foreach (string addr in getResult.Split(','))
				{
					IPAddress address = IPAddress.Parse(addr);
					dnsData.Add(address);
				}
			}
			catch
			{
				return dnsData;
			}
			return dnsData;
		}

		static string Get_Correct_Prefix(string hostNamePrefix, List<string> contours, NameValueCollection contourConfig)
		{
			string hostSpecialPrefix = "";
			foreach (string contour in contours)
			{
				foreach (var key in contourConfig.AllKeys)
				{
					List<string> redisContours = new List<string>();
					foreach (string cName in contourConfig[key].Split(';'))
					{
						redisContours.Add(cName.Trim());
					}
					if (redisContours.Contains(contour))
					{
						hostSpecialPrefix = key;
						return string.Format("{0}{1}", hostSpecialPrefix, hostNamePrefix);
					}
				}
			}
			return hostNamePrefix;
		}

		static List<string> Get_Contours(string rawData, string hostName) //Тут нужно обернуть на предмет отсутствия данных!
		{
			List<string> contourList = new List<string>();
			try
			{ 
				dynamic jsonObj = JsonConvert.DeserializeObject(rawData);
				string getResult = jsonObj.GET;
				dynamic redisObject = JsonConvert.DeserializeObject(getResult);
				dynamic envObject = redisObject.hosts_sites[hostName]["Env"];
				JArray JenvArray = (JArray)envObject;
				foreach (var item in JenvArray.Children())
				{
					contourList.Add(item["name"].ToString());
				}
			}
			catch
			{
				return contourList;
			}
			return contourList;
		}

		static string Get_Data_From_Redis(string uri)
		{
			var redEncoding = Encoding.UTF8;
			HttpWebRequest request = (HttpWebRequest)WebRequest.Create(uri);
			request.AutomaticDecompression = DecompressionMethods.GZip | DecompressionMethods.Deflate;
			request.Timeout = 5000;
			try
			{
				using (HttpWebResponse response = (HttpWebResponse)request.GetResponse())
				using (Stream stream = response.GetResponseStream())
				using (StreamReader reader = new StreamReader(stream, encoding: redEncoding))
				{
					return reader.ReadToEnd();
				}
			}
			catch
			{
				Console.WriteLine(errorMessages["redisError"]);
				Environment.Exit(0);
				return "Error";
			}
		}

		private static bool Check_One_Network(string firstIP, string secondIP, string subNet)
		{
			uint subnetmaskInInt = ConvertIPToUint(subNet);
			uint firstIPInInt = ConvertIPToUint(firstIP);
			uint secondIPInInt = ConvertIPToUint(secondIP);
			uint networkPortionofFirstIP = firstIPInInt & subnetmaskInInt;
			uint networkPortionofSecondIP = secondIPInInt & subnetmaskInInt;
			if (networkPortionofFirstIP == networkPortionofSecondIP)
				return true;
			else
				return false;
		}

		static string get_zabbbix_address()
		{
			string redisAddress = "";
			try
			{
				string configPath = @"C:\Program Files\Zabbix Agent\conf\zabbix_agentd.conf";
				string serverActive = "ServerActive";
				
				string[] lines = File.ReadAllLines(configPath);
				foreach (string line in lines)
				{
					if (line.Contains(serverActive))
					{
						if (!line.StartsWith("#"))
						{
							redisAddress = line.Split('=')[1].Split(',')[0].Split(':')[0] + ":7379";
							break;
						}
					}
				}
			}
			catch
			{
				redisAddress = ConfigurationManager.AppSettings["redisHost"];
			}
			
			return redisAddress;
		}

		static public uint ConvertIPToUint(string ipAddress)
		{
			System.Net.IPAddress iPAddress = System.Net.IPAddress.Parse(ipAddress);
			byte[] byteIP = iPAddress.GetAddressBytes();
			uint ipInUint = (uint)byteIP[3] << 24;
			ipInUint += (uint)byteIP[2] << 16;
			ipInUint += (uint)byteIP[1] << 8;
			ipInUint += (uint)byteIP[0];
			return ipInUint;
		}
	}
}
