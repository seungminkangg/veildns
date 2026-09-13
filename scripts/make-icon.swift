import AppKit
import Foundation

let destination = URL(fileURLWithPath: CommandLine.arguments[1]).appendingPathComponent("VeilDNS.iconset")
try FileManager.default.createDirectory(at: destination, withIntermediateDirectories: true)
for points in [16, 32, 128, 256, 512] {
    for scale in [1, 2] {
        let pixels = points * scale
        let bitmap = NSBitmapImageRep(bitmapDataPlanes: nil, pixelsWide: pixels, pixelsHigh: pixels,
            bitsPerSample: 8, samplesPerPixel: 4, hasAlpha: true, isPlanar: false,
            colorSpaceName: .deviceRGB, bytesPerRow: 0, bitsPerPixel: 0)!
        NSGraphicsContext.saveGraphicsState()
        NSGraphicsContext.current = NSGraphicsContext(bitmapImageRep: bitmap)
        let unit = CGFloat(pixels) / 1024
        let transform = NSAffineTransform()
        transform.scale(by: unit)
        transform.concat()
        let background = NSBezierPath(roundedRect: NSRect(x: 48, y: 48, width: 928, height: 928), xRadius: 210, yRadius: 210)
        let gradient = NSGradient(starting: NSColor(srgbRed: 0.08, green: 0.16, blue: 0.27, alpha: 1),
                                  ending: NSColor(srgbRed: 0.04, green: 0.07, blue: 0.13, alpha: 1))!
        gradient.draw(in: background, angle: -70)
        let shield = NSBezierPath()
        shield.move(to: NSPoint(x: 512, y: 798))
        shield.line(to: NSPoint(x: 754, y: 702))
        shield.line(to: NSPoint(x: 731, y: 460))
        shield.curve(to: NSPoint(x: 512, y: 230), controlPoint1: NSPoint(x: 719, y: 357), controlPoint2: NSPoint(x: 589, y: 262))
        shield.curve(to: NSPoint(x: 293, y: 460), controlPoint1: NSPoint(x: 435, y: 262), controlPoint2: NSPoint(x: 305, y: 357))
        shield.line(to: NSPoint(x: 270, y: 702))
        shield.close()
        NSColor(srgbRed: 0.31, green: 0.89, blue: 0.76, alpha: 1).setStroke()
        shield.lineWidth = 34
        shield.lineJoinStyle = .round
        shield.stroke()
        let veil = NSBezierPath()
        veil.move(to: NSPoint(x: 381, y: 620))
        veil.line(to: NSPoint(x: 496, y: 403))
        veil.move(to: NSPoint(x: 550, y: 458))
        veil.line(to: NSPoint(x: 655, y: 658))
        veil.lineWidth = 56
        veil.lineCapStyle = .round
        NSColor.white.setStroke()
        veil.stroke()
        NSGraphicsContext.restoreGraphicsState()
        let suffix = scale == 2 ? "@2x" : ""
        let filename = "icon_\(points)x\(points)\(suffix).png"
        try bitmap.representation(using: .png, properties: [:])!.write(to: destination.appendingPathComponent(filename))
    }
}
