# Example policy to allow SSH connections without updating the SSH configuration via volume mounts
package agent_policy

import future.keywords.in
import future.keywords.if
import future.keywords.every

default AddARPNeighborsRequest := true
default AddSwapRequest := true
default CloseStdinRequest := true
default CreateSandboxRequest := true
default DestroySandboxRequest := true
default GetMetricsRequest := true
default GetOOMEventRequest := true
default GuestDetailsRequest := true
default ListInterfacesRequest := true
default ListRoutesRequest := true
default MemHotplugByProbeRequest := true
default OnlineCPUMemRequest := true
default PauseContainerRequest := true
default PullImageRequest := true
default ReadStreamRequest := true
default RemoveContainerRequest := true
default RemoveStaleVirtiofsShareMountsRequest := true
default ReseedRandomDevRequest := true
default ResumeContainerRequest := true
default SetGuestDateTimeRequest := true
default SetPolicyRequest := true
default SignalProcessRequest := true
default StartContainerRequest := true
default StartTracingRequest := true
default StatsContainerRequest := true
default StopTracingRequest := true
default TtyWinResizeRequest := true
default UpdateContainerRequest := true
default UpdateEphemeralMountsRequest := true
default UpdateInterfaceRequest := true
default UpdateRoutesRequest := true
default WaitProcessRequest := true
default WriteStreamRequest := true

default CopyFileRequest := false
default ReadStreamRequest := false
default ExecProcessRequest := false
default CreateContainerRequest := false

CopyFileRequest if {
    not exists_disabled_path
}

exists_disabled_path {
    some disabled_path in policy_data.disabled_paths
    contains(input.path, disabled_path)
}

CreateContainerRequest if {
        every storage in input.storages {
        some allowed_image in policy_data.allowed_images
        storage.source == allowed_image
    }
}


policy_data := {
        "disabled_paths": [
               "ssh",
               "authorized_keys",
               "sshd_config"
        ],

        "allowed_images": [
                "pause",
                "quay.io/bpradipt/ssh-server@sha256:3f6cf765ff47a8b180272f1040ab713e08332980834423129fbce80269cf7529",
                "quay.io/fedora/fedora@sha256:97deaad057a6c346c5158f7ae100b2f97de128581d6e5d8f35246fc5be66048d",
        ]
}