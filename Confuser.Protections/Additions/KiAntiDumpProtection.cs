using System.Linq;
using Confuser.Core;
using Confuser.Core.Helpers;
using Confuser.Core.Services;
using Confuser.Renamer;
using dnlib.DotNet;
using dnlib.DotNet.Emit;

namespace Confuser.Protections.Additions {
	[BeforeProtection("Ki.ControlFlow", "Ki.ControlFlow2")]
	internal class KiAntiDumpProtection : Protection {
		public const string _Id = "ki anti dump";
		public const string _FullId = "Ki.AntiDump2";

		public override string Name => "Ki Anti Dump Protection";
		public override string Description => "This protection prevents memory dumping (Ki variant).";
		public override string Id => _Id;
		public override string FullId => _FullId;
		public override ProtectionPreset Preset => ProtectionPreset.None;

		protected override void Initialize(ConfuserContext context) { }

		protected override void PopulatePipeline(ProtectionPipeline pipeline) {
			pipeline.InsertPreStage(PipelineStage.ProcessModule, new KiAntiDumpPhase(this));
		}

		class KiAntiDumpPhase : ProtectionPhase {
			public KiAntiDumpPhase(KiAntiDumpProtection parent) : base(parent) { }

			public override ProtectionTargets Targets => ProtectionTargets.Modules;
			public override string Name => "Ki anti-dump injection";

			protected override void Execute(ConfuserContext context, ProtectionParameters parameters) {
				var rtType = context.Registry.GetService<IRuntimeService>().GetRuntimeType("Confuser.Runtime.KiAntiDump");
				var marker = context.Registry.GetService<IMarkerService>();
				var name = context.Registry.GetService<INameService>();

				foreach (var module in parameters.Targets.OfType<ModuleDef>()) {
					var members = InjectHelper.Inject(rtType, module.GlobalType, module);
					var cctor = module.GlobalType.FindStaticConstructor();
					var init = (MethodDef)members.Single(method => method.Name == "Initialize");
					cctor.Body.Instructions.Insert(0, Instruction.Create(OpCodes.Call, init));

					foreach (var member in members)
						name.MarkHelper(member, marker, (Protection)Parent);
				}
			}
		}
	}
}
