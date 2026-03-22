using System.Collections.Generic;
using System.IO;
using System.Linq;
using System.Security.Cryptography;
using System.Text;
using Confuser.Core;
using Confuser.Core.Helpers;
using Confuser.Core.Services;
using Confuser.Renamer;
using dnlib.DotNet;
using dnlib.DotNet.Emit;
using dnlib.DotNet.Writer;

namespace Confuser.Protections.Additions {
	[BeforeProtection("Ki.ControlFlow")]
	internal class MD5HashCheckProtection : Protection {
		public const string _Id = "md5 check";
		public const string _FullId = "Ki.md5";

		public override string Name => "MD5 Hash Check Protection";
		public override string Description => "This protection checks the MD5 hash of the assembly at runtime.";
		public override string Id => _Id;
		public override string FullId => _FullId;
		public override ProtectionPreset Preset => ProtectionPreset.None;

		protected override void Initialize(ConfuserContext context) { }

		protected override void PopulatePipeline(ProtectionPipeline pipeline) {
			pipeline.InsertPreStage(PipelineStage.ProcessModule, new MD5HashPhase(this));
		}

		class MD5HashPhase : ProtectionPhase {
			public MD5HashPhase(MD5HashCheckProtection parent) : base(parent) { }

			public override ProtectionTargets Targets => ProtectionTargets.Modules;
			public override string Name => "MD5 hash check injection";

			protected override void Execute(ConfuserContext context, ProtectionParameters parameters) {
				var rtType = context.Registry.GetService<IRuntimeService>().GetRuntimeType("Confuser.Runtime.MD5");
				var marker = context.Registry.GetService<IMarkerService>();
				var name = context.Registry.GetService<INameService>();

				context.CurrentModuleWriterOptions.WriterEvent += InjectHash;

				foreach (ModuleDef module in parameters.Targets.OfType<ModuleDef>()) {
					IEnumerable<IDnlibDef> members = InjectHelper.Inject(rtType, module.GlobalType, module);
					MethodDef cctor = module.GlobalType.FindStaticConstructor();
					var init = (MethodDef)members.Single(method => method.Name == "Initialize");
					cctor.Body.Instructions.Insert(0, Instruction.Create(OpCodes.Call, init));

					foreach (IDnlibDef member in members)
						name.MarkHelper(member, marker, (Protection)Parent);
				}
			}

			static string Hash(byte[] data) {
				using (var md5 = System.Security.Cryptography.MD5.Create()) {
					byte[] hash = md5.ComputeHash(data);
					var sb = new StringBuilder();
					foreach (byte b in hash)
						sb.Append(b.ToString("x2"));
					return sb.ToString();
				}
			}

			void InjectHash(object sender, ModuleWriterEventArgs e) {
				if (e.Event == ModuleWriterEvent.End) {
					var writer = (ModuleWriterBase)sender;
					var st = new StreamReader(writer.DestinationStream);
					var a = new BinaryReader(st.BaseStream);
					a.BaseStream.Position = 0;
					var data = a.ReadBytes((int)(st.BaseStream.Length - 32));
					var enc = Encoding.Default.GetBytes(Hash(data));
					writer.DestinationStream.Position = writer.DestinationStream.Length - enc.Length;
					writer.DestinationStream.Write(enc, 0, enc.Length);
				}
			}
		}
	}
}
