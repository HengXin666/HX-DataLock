import Foundation

struct Helpers {
    static let shared = Helpers()
    func loadAdjacencyGraphs() -> [String: [String: [String?]]] {
        guard let path = Bundle.module.url(forResource: "adjacency-graphs", withExtension: "json"),
              let data = try? Data(contentsOf: path) else {
            return [:]
        }

        do {
            guard let raw = try JSONSerialization.jsonObject(with: data) as? [String: Any] else { return [:] }
            var parsed: [String: [String: [String?]]] = [:]
            for (layout, keys) in raw {
                guard let keys = keys as? [String: Any] else { continue }
                var neighborsByKey: [String: [String?]] = [:]
                for (key, neighbors) in keys {
                    guard let neighbors = neighbors as? [Any] else { continue }
                    neighborsByKey[key] = neighbors.map { item in
                        item is NSNull ? nil : item as? String
                    }
                }
                parsed[layout] = neighborsByKey
            }
            return parsed
        } catch {
            print("Error parsing adjacency graphs: \(error)")
            return [:]
        }
    }

    func loadFrequencyLists() -> [String: [String]] {
        guard let path = Bundle.module.url(forResource: "frequency-lists", withExtension: "json"),
              let data = try? Data(contentsOf: path) else {
            return [:]
        }

        do {
            guard let json: [String: [String]] = try JSONSerialization.jsonObject(with: data) as? [String: [String]] else {
                return [:]
            }
            return json
        } catch {
            print("Error parsing frequency lists: \(error)")
            return [:]
        }
    }

    func buildRankedDict(_ orderedList: [String]) -> [String: Int] {
        var result: [String: Int] = [:]
        for (i, word) in orderedList.enumerated() {
            result[word] = i + 1
        }
        return result
    }
}
