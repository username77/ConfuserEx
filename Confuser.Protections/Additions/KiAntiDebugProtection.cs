using System.Collections.Generic;
using System.Linq;
using Confuser.Core;
using Confuser.Core.Helpers;
using Confuser.Core.Services;
using Confuser.Renamer;
using dnlib.DotNet;
using dnlib.DotNet.Emit;

namespace Confuser.Protections.Additions {
	[BeforeProtection("Ki.ControlFlow", "Ki.ControlFlow2")]
	internal class KiAntiDebugProtection : Protection {
		public const string _Id = "ki anti debug";
		public const string _FullId = "Ki.AntiDebug2";

		public override string Name => "Ki Anti Debug Protection";
		public override string Description => "This protection prevents debugging (Ki variant).";
		public override string Id => _Id;
		public override string FullId => _FullId;
		public override ProtectionPreset Preset => ProtectionPreset.None;

		protected override void Initialize(ConfuserContext context) { }

		protected override void PopulatePipeline(ProtectionPipeline pipeline) {
			pipeline.InsertPreStage(PipelineStage.ProcessModule, new KiAntiDebugPhase(this));
		}

		class KiAntiDebugPhase : ProtectionPhase {
			public KiAntiDebugPhase(KiAntiDebugProtection parent) : base(parent) { }

			public override ProtectionTargets Targets => ProtectionTargets.Modules;
			public override string Name => "Ki anti-debug injection";

			protected override void Execute(ConfuserContext context, ProtectionParameters parameters) {
				var rtType = context.Registry.GetService<IRuntimeService>().GetRuntimeType("Confuser.Runtime.KiAntiDebug");
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
