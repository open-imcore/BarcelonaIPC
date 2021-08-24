//
//  IPCReceiver.swift
//  BarcelonaIPC
//
//  Created by Eric Rabil on 8/12/21.
//  Copyright © 2021 Eric Rabil. All rights reserved.
//

import Foundation
import Swexy

@_silgen_name("bootstrap_check_in")
func bootstrap_check_in(_ bootstrap_port: mach_port_t, _ service_name: UnsafePointer<CChar>, _ port: UnsafeMutablePointer<mach_port_t>) -> kern_return_t

#if os(iOS)
public typealias PortMessage = NSObject

private extension PortMessage {
    var components: [Any]? {
        self.value(forKey: "components") as? [Any]
    }
    
    var sendPort: Port? {
        self.value(forKey: "sendPort") as? Port
    }
}
#endif

public class IPCReceiver<PayloadType: RawRepresentable>: IPCWrapper<PayloadType>, PortDelegate where PayloadType.RawValue == UInt, PayloadType: Codable {
    public typealias ReceiverCallback = (Payload, IPCSender<PayloadType>?, IPCReceiver) -> ()
    
    public static func anonymousReceiver(_ responseHandler: @escaping ReceiverCallback) -> IPCReceiver {
        IPCReceiver(port: IPCReceivePort(), mine: true, handleResponse: responseHandler)
    }
    
    public static func serverReceiver(named name: String, _ responseHandler: @escaping ReceiverCallback) -> IPCReceiver {
        var existingPort: mach_port_t = 0
        
        if bootstrap_check_in(bootstrap_port, name, &existingPort) == KERN_SUCCESS, existingPort != 0 {
            return IPCReceiver(port: IPCWrapPort(existingPort), mine: true, handleResponse: responseHandler)
        }
        
        let receiver = IPCReceiver(port: IPCReceivePort(), mine: true, handleResponse: responseHandler)
        
        guard receiver.registerPort(withName: name) == KERN_SUCCESS else {
            fatalError("failed to register with bootstrap")
        }
        
        return receiver
    }
    
    public let handleResponse: ReceiverCallback
    
    public init(port: Port, mine: Bool, handleResponse: @escaping ReceiverCallback) {
        self.handleResponse = handleResponse
        super.init(port: port, mine: mine)
        
        port.setDelegate(self)
    }

    public func handle(_ message: PortMessage) {
        guard let payloadData = message.components?.first as? Data, let payload = try? decoder.decode(Payload.self, from: payloadData) else {
            return
        }
        
        if let sendPort = message.sendPort {
            handleResponse(payload, IPCSender(port: sendPort, mine: false), self)
        } else {
            handleResponse(payload, nil, self)
        }
    }
    
    public func registerPort(withName name: String) -> kern_return_t {
        guard let port = port as? NSMachPort else {
            return -1
        }
        
        return bootstrap_register(bootstrap_port, name, port.machPort)
    }
    
    public func registerPort(withName name: String, forUID uid: uid_t) throws -> kern_return_t {
        try xpc_impersonate_user(uid) {
            self.registerPort(withName: name)
        }
    }
}
