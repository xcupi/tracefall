using Microsoft.SqlServer.XEvent.XELite;
using System.Globalization;
using System.Text.Json;
using System.Security.Cryptography;
// File constructor only. No SQL connection, discovery, package restore or downloads.
static object Value(object v) {
 if (v == null) return new { type="null", value=(object)null };
 string type=v.GetType().FullName!;
 object x=v switch {
  byte[] b => Convert.ToBase64String(b),
  DateTimeOffset d => d.ToString("O",CultureInfo.InvariantCulture),
  DateTime d => d.ToString("O",CultureInfo.InvariantCulture),
  long or ulong => Convert.ToString(v,CultureInfo.InvariantCulture)!,
  string or bool or byte or sbyte or short or ushort or int or uint or double or float or decimal => v,
  _ => Convert.ToString(v,CultureInfo.InvariantCulture)!
 };
 // XEActivityId is internal to XELite: preserve both GUID and sequence rather
 // than allowing System.Text.Json to silently serialize it as {}.
 if(type.EndsWith("XEActivityId",StringComparison.Ordinal)) {
  string text=Convert.ToString(v,CultureInfo.InvariantCulture)!;
  int split=text.LastIndexOf(':');
  if(split<0 || !Guid.TryParse(text[..split],out var id) || !ulong.TryParse(text[(split+1)..],out var seq)) throw new IOException("invalid activity identity");
  return new {type,value=x,activity_id=id.ToString(),activity_sequence=seq.ToString(CultureInfo.InvariantCulture)};
 }
 return new {type,value=x};
}
static object Values(IReadOnlyDictionary<string,object> d) => d.OrderBy(x=>x.Key,StringComparer.Ordinal).ToDictionary(x=>x.Key,x=>Value(x.Value));
long n=0,total=0;
try {
 if(args.Length!=1 || args[0]!="/evidence") throw new IOException("one sandboxed file required");
 using var input=new FileStream(args[0],FileMode.Open,FileAccess.Read,FileShare.Read);
 string sourceHash=Convert.ToHexString(SHA256.HashData(input)).ToLowerInvariant();input.Position=0;
 Console.WriteLine(JsonSerializer.Serialize(new{kind="header",schema=1,reader="XELite/2024.2.5.1",checksum=true,source_sha256=sourceHash,source_size=input.Length.ToString(CultureInfo.InvariantCulture)}));
 var stream=new XEFileEventStreamer(input,shouldVerifyChecksum:true);
 await stream.ReadEventStream(()=>Task.CompletedTask,e=> {
  if(n>=10000)throw new IOException("record_cap");
  var line=JsonSerializer.Serialize(new{kind="event",ordinal=(n+1).ToString(CultureInfo.InvariantCulture),name=e.Name,uuid=e.UUID,timestamp=e.Timestamp.ToString("O",CultureInfo.InvariantCulture),start_offset=Convert.ToString(e.XEventStartOffsetInBytes,CultureInfo.InvariantCulture),end_offset=Convert.ToString(e.XEventEndOffsetInBytes,CultureInfo.InvariantCulture),size=Convert.ToString(e.XEventSizeInBytes,CultureInfo.InvariantCulture),fields=Values(e.Fields),actions=Values(e.Actions)});
  int bytes=System.Text.Encoding.UTF8.GetByteCount(line)+1;
  if(bytes>1024*1024 || total+bytes>16*1024*1024)throw new IOException("output_cap");
  total+=bytes;n++;Console.WriteLine(line);return Task.CompletedTask;
 },new CancellationTokenSource(TimeSpan.FromSeconds(30)).Token);
 Console.WriteLine(JsonSerializer.Serialize(new{kind="final",status="complete",records=n}));
} catch { Console.Error.WriteLine("offline reader failed (corrupt, unsupported or limit)");Environment.ExitCode=2; }
