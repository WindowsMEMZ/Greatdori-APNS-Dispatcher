//
//  main.swift
//  Greatdori-APNS-Dispatcher
//
//  Created by Mark Chan on 9/11/25.
//

import APNS
import DoriKit
import NIOCore
import NIOPosix
import APNSCore
import CryptoKit
import Foundation
import SwiftyJSON

let dateResponse = try! JSON(data: urlData("https://api.push.greatdori.memz.top/datemeta/updated/get"))
let timestamp = dateResponse["timestamp"].double!
if timestamp < 100 { fatalError("Timestamp is too low") }

let latestNews = await DoriFrontend.News.list()!
let newsDiff = latestNews.prefix { item in
    item.timestamp.timeIntervalSince1970 > timestamp
}

_ = urlData("https://api.push.greatdori.memz.top/datemeta/updated/set/\(Date.now.timeIntervalSince1970)")

guard !newsDiff.isEmpty else {
    print("No new news, exiting")
    exit(0)
}

let tokensResponse = try! JSON(data: urlData("https://api.push.greatdori.memz.top/listAll"))
let tokens = tokensResponse["tokens"].compactMap {
    decryptDeviceToken($0.1.stringValue, secret: ProcessInfo.processInfo.environment["TOKEN_LIST_PWD"]!)
}

let apnsClient = APNSClient(
    configuration: .init(
        authenticationMethod: .jwt(
            privateKey: try! .init(pemRepresentation: ProcessInfo.processInfo.environment["APNS_PRIVATE_KEY"]!),
            keyIdentifier: ProcessInfo.processInfo.environment["APNS_KEY_ID"]!,
            teamIdentifier: ProcessInfo.processInfo.environment["APNS_TEAM_ID"]!
        ),
        environment: .production
    ),
    eventLoopGroupProvider: .shared(MultiThreadedEventLoopGroup.singleton),
    responseDecoder: JSONDecoder(),
    requestEncoder: JSONEncoder()
)

for token in tokens {
    for news in newsDiff {
        LimitedTaskQueue.shared.addTask {
            let notifBody: APNSAlertNotificationContent.StringValue? = switch news.timeMark {
            case .willStartAfter(let interval):
                if interval == 1 {
                    .localized(key: "News.time-mark.will-start-after.one", arguments: ["\(interval)"])
                } else {
                    .localized(key: "News.time-mark.will-start-after.other", arguments: ["\(interval)"])
                }
            case .willEndAfter(let interval):
                if interval == 1 {
                    .localized(key: "News.time-mark.will-end-after.one", arguments: ["\(interval)"])
                } else {
                    .localized(key: "News.time-mark.will-end-after.other", arguments: ["\(interval)"])
                }
            case .willEndToday:
                    .localized(key: "News.time-mark.will-end-today", arguments: [])
            case .hasEnded:
                    .localized(key: "News.time-mark.has-ended", arguments: [])
            case .hasPublished:
                    .localized(key: "News.time-mark.has-published", arguments: [])
            case .willStartToday:
                    .localized(key: "News.time-mark.will-start-today", arguments: [])
            @unknown default: nil
            }
            _ = try? await apnsClient.sendAlertNotification(
                .init(
                    alert: .init(
                        title: .raw(news.subject),
                        body: notifBody
                    ),
                    expiration: .immediately,
                    priority: .consideringDevicePower,
                    topic: "com.memz233.Greatdori",
                    payload: NotificationPayload(),
                    badge: newsDiff.count,
                    sound: .default
                ),
                deviceToken: token
            )
        }
    }
}

await LimitedTaskQueue.shared.waitUntilAllFinished()

struct NotificationPayload: Codable {}

class LimitedTaskQueue {
    static var shared: LimitedTaskQueue = .init(limit: 30)
    
    private let semaphore: DispatchSemaphore
    private let queue = DispatchQueue(label: "com.memz233.Greatdori.APNS-Dispatcher.limited-task-queue", attributes: .concurrent)
    
    private let lock = NSLock()
    private var runningTasks = 0
    private let allDoneSemaphore = DispatchSemaphore(value: 0)
    
    init(limit: Int) {
        self.semaphore = DispatchSemaphore(value: limit)
    }
    
    func addTask(_ task: @escaping () async -> Void) {
        incrementRunning()
        queue.async {
            self.semaphore.wait()
            Task {
                await task()
                self.semaphore.signal()
                self.decrementRunning()
            }
        }
    }
    
    func waitUntilAllFinished() async {
        await withCheckedContinuation { continuation in
            Task.detached {
                self.lock.lock()
                if self.runningTasks == 0 {
                    self.lock.unlock()
                    continuation.resume()
                    return
                }
                self.lock.unlock()
                
                self.allDoneSemaphore.wait()
                continuation.resume()
            }
        }
    }
    
    private func incrementRunning() {
        lock.lock()
        runningTasks += 1
        lock.unlock()
    }
    
    private func decrementRunning() {
        lock.lock()
        runningTasks -= 1
        if runningTasks == 0 {
            allDoneSemaphore.signal()
        }
        lock.unlock()
    }
}

func urlData(_ urlString: String) -> Data {
    for _ in 0..<10 {
        if let result = try? Data(contentsOf: URL(string: urlString)!) {
            return result
        }
    }
    fatalError("Failed to fetch: \(urlString)")
}

func decryptDeviceToken(_ encrypted: String, secret: String) -> String? {
    guard let fullData = Data(base64Encoded: encrypted),
          let keyData = secret.data(using: .utf8) else {
        return nil
    }
    
    let key = SymmetricKey(data: keyData)
    
    let ivLength = 12
    guard fullData.count > ivLength else { return nil }
    let ivData = fullData.prefix(ivLength)
    let cipherData = fullData.suffix(from: ivLength)
    
    do {
        let sealedBox = try AES.GCM.SealedBox(nonce: AES.GCM.Nonce(data: ivData), ciphertext: cipherData, tag: cipherData.suffix(16))
        
        let actualCipher = cipherData.dropLast(16)
        let box = try AES.GCM.SealedBox(nonce: AES.GCM.Nonce(data: ivData), ciphertext: actualCipher, tag: cipherData.suffix(16))
        
        let decryptedData = try AES.GCM.open(box, using: key)
        return String(data: decryptedData, encoding: .utf8)
    } catch {
        print("Failed to decrypt '\(encrypted)': \(error)")
        return nil
    }
}
