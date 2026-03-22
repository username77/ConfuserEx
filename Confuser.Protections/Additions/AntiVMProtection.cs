using System.Collections.Generic;
using System.Linq;
using Confuser.Core;
using Confuser.Core.Helpers;
using Confuser.Core.Services;
using Confuser.Renamer;
using dnlib.DotNet;
using dnlib.DotNet.Emit;

namespace Confuser.Protections.Additions {
	internal class AntiVMProtection : Protection {
		public const string _Id = "anti vm";
		public const string _FullId = "Ki.AntiVM";

		public override string Name => "Anti Virtual Machine Protection";
		public override string Description => "This protection prevents the assembly from running in a VM.";
		public override string Id => _Id;
		public override string FullId => _FullId;
		public override ProtectionPreset Preset => ProtectionPreset.None;

		protected override void Initialize(ConfuserContext context) { }

		protected override void PopulatePipeline(ProtectionPipeline pipeline) {
			pipeline.InsertPreStage(PipelineStage.ProcessModule, new AntiVMPhase(this));
		}

		class AntiVMPhase : ProtectionPhase {
			public AntiVMPhase(AntiVMProtection parent) : base(parent) { }

			public override ProtectionTargets Targets => ProtectionTargets.Modules;
			public override string Name => "Anti VM injection";

			protected override void Execute(ConfuserContext context, ProtectionParameters parameters) {
				var rtType = context.Registry.GetService<IRuntimeService>().GetRuntimeType("Confuser.Runtime.AntiVM");
				var marker = context.Registry.GetService<IMarkerService>();
				var name = context.Registry.GetService<INameService>();

				foreach (ModuleDef module in parameters.Targets.OfType<ModuleDef>()) {
					IEnumerable<IDnlibDef> members = InjectHelper.Inject(rtType, module.GlobalType, module);
					MethodDef cctor = module.GlobalType.FindStaticConstructor();
					var init = (MethodDef)members.Single(method => method.Name == "Initialize");
					cctor.Body.Instructions.Insert(0, Instruction.Create(OpCodes.Call, init));

					foreach (IDnlibDef member in members)
						name.MarkHelper(member, marker, (Protection)Parent);
				}
			}
		}
	}
}
