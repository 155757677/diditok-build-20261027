import UIKit
import PhotosUI
import Vision
import CoreImage

/// 主界面：标题 + 结果 + 两个按钮（扫描 / 导入二维码）。
/// 左边缘向右滑 = 关闭程序。
final class HomeViewController: UIViewController {

    private let titleLabel = UILabel()
    private let resultLabel = UILabel()
    private let detailLabel = UILabel()
    private let scanButton = UIButton(type: .system)
    private let importButton = UIButton(type: .system)
    private let hintLabel = UILabel()

    private var password = ""

    private let brand = UIColor(red: 1/255, green: 159/255, blue: 171/255, alpha: 1)

    override func viewDidLoad() {
        super.viewDidLoad()
        view.backgroundColor = .black
        buildUI()

        let close = UIScreenEdgePanGestureRecognizer(target: self, action: #selector(onEdgeClose(_:)))
        close.edges = .left
        view.addGestureRecognizer(close)
    }

    private func buildUI() {
        titleLabel.text = "奕派解码器"
        titleLabel.textColor = .white
        titleLabel.font = .systemFont(ofSize: 20, weight: .semibold)
        titleLabel.textAlignment = .center
        titleLabel.translatesAutoresizingMaskIntoConstraints = false
        view.addSubview(titleLabel)

        resultLabel.text = "——"
        resultLabel.textColor = .white
        resultLabel.font = .monospacedSystemFont(ofSize: 52, weight: .bold)
        resultLabel.adjustsFontSizeToFitWidth = true
        resultLabel.isUserInteractionEnabled = true
        resultLabel.translatesAutoresizingMaskIntoConstraints = false
        view.addSubview(resultLabel)
        resultLabel.addGestureRecognizer(UITapGestureRecognizer(target: self, action: #selector(onCopy)))
        resultLabel.addGestureRecognizer(UILongPressGestureRecognizer(target: self, action: #selector(onShowDetail(_:))))

        detailLabel.textColor = .secondaryLabel
        detailLabel.font = .systemFont(ofSize: 13)
        detailLabel.textAlignment = .center
        detailLabel.numberOfLines = 2
        detailLabel.isHidden = true
        detailLabel.translatesAutoresizingMaskIntoConstraints = false
        view.addSubview(detailLabel)

        func style(_ b: UIButton, filled: Bool) {
            b.titleLabel?.font = .systemFont(ofSize: 18, weight: .semibold)
            b.layer.cornerRadius = 12
            b.layer.masksToBounds = true
            b.heightAnchor.constraint(equalToConstant: 52).isActive = true
            if filled {
                b.backgroundColor = brand
                b.setTitleColor(.white, for: .normal)
            } else {
                b.backgroundColor = UIColor(white: 1, alpha: 0.12)
                b.setTitleColor(brand, for: .normal)
                b.layer.borderWidth = 1
                b.layer.borderColor = brand.cgColor
            }
            b.translatesAutoresizingMaskIntoConstraints = false
        }
        scanButton.setTitle("扫描二维码", for: .normal)
        scanButton.addTarget(self, action: #selector(onScan), for: .touchUpInside)
        style(scanButton, filled: true)
        view.addSubview(scanButton)

        importButton.setTitle("导入二维码", for: .normal)
        importButton.addTarget(self, action: #selector(onImport), for: .touchUpInside)
        style(importButton, filled: false)
        view.addSubview(importButton)

        hintLabel.textColor = .secondaryLabel
        hintLabel.font = .systemFont(ofSize: 13)
        hintLabel.textAlignment = .center
        hintLabel.numberOfLines = 2
        hintLabel.translatesAutoresizingMaskIntoConstraints = false
        view.addSubview(hintLabel)

        let g = view.safeAreaLayoutGuide
        NSLayoutConstraint.activate([
            titleLabel.topAnchor.constraint(equalTo: g.topAnchor, constant: 6),
            titleLabel.leadingAnchor.constraint(equalTo: view.leadingAnchor, constant: 12),
            titleLabel.trailingAnchor.constraint(equalTo: view.trailingAnchor, constant: -12),

            resultLabel.centerYAnchor.constraint(equalTo: view.centerYAnchor, constant: -70),
            resultLabel.leadingAnchor.constraint(equalTo: view.leadingAnchor, constant: 16),
            resultLabel.trailingAnchor.constraint(equalTo: view.trailingAnchor, constant: -16),
            resultLabel.heightAnchor.constraint(equalToConstant: 68),

            detailLabel.topAnchor.constraint(equalTo: resultLabel.bottomAnchor, constant: 2),
            detailLabel.leadingAnchor.constraint(equalTo: view.leadingAnchor, constant: 16),
            detailLabel.trailingAnchor.constraint(equalTo: view.trailingAnchor, constant: -16),

            scanButton.topAnchor.constraint(equalTo: view.centerYAnchor, constant: 40),
            scanButton.leadingAnchor.constraint(equalTo: view.leadingAnchor, constant: 40),
            scanButton.trailingAnchor.constraint(equalTo: view.trailingAnchor, constant: -40),

            importButton.topAnchor.constraint(equalTo: scanButton.bottomAnchor, constant: 14),
            importButton.leadingAnchor.constraint(equalTo: view.leadingAnchor, constant: 40),
            importButton.trailingAnchor.constraint(equalTo: view.trailingAnchor, constant: -40),

            hintLabel.bottomAnchor.constraint(equalTo: g.bottomAnchor, constant: -10),
            hintLabel.leadingAnchor.constraint(equalTo: view.leadingAnchor, constant: 16),
            hintLabel.trailingAnchor.constraint(equalTo: view.trailingAnchor, constant: -16),
        ])
    }

    // MARK: - 结果

    func show(_ r: DongfengDecoder.Output, from source: String) {
        password = r.password
        resultLabel.textColor = .white
        resultLabel.text = r.password
        detailLabel.isHidden = true
        detailLabel.text = "随机码 \(r.code) · 车型串 \"\(r.tag)\" · \(source)"
        hint(.green("点一下数字即复制"))
        UIImpactFeedbackGenerator(style: .medium).impactOccurred()
    }

    func showError(_ message: String) {
        password = ""
        resultLabel.text = "——"
        resultLabel.textColor = .secondaryLabel
        detailLabel.isHidden = true
        hint(.gray(message))
        UINotificationFeedbackGenerator().notificationOccurred(.error)
    }

    @objc private func onCopy() {
        guard !password.isEmpty else { return }
        UIPasteboard.general.string = password
        hint(.green("已复制 \(password)"))
    }

    @objc private func onShowDetail(_ gr: UILongPressGestureRecognizer) {
        guard gr.state == .began, !password.isEmpty else { return }
        detailLabel.isHidden.toggle()
    }

    @objc private func onEdgeClose(_ gr: UIScreenEdgePanGestureRecognizer) {
        guard gr.state == .ended else { return }
        let t = gr.translation(in: view)
        if t.x > 60 { exit(0) }        // 左边缘向右滑：直接关掉程序
    }

    // MARK: - 入口

    @objc private func onScan() {
        let vc = ScanViewController()
        vc.modalPresentationStyle = .fullScreen
        vc.onResult = { [weak self] out in
            guard let self = self else { return }
            self.show(out, from: "实时扫码")
        }
        present(vc, animated: true)
    }

    @objc private func onImport() {
        if #available(iOS 14.0, *) {
            var cfg = PHPickerConfiguration()
            cfg.filter = .images
            cfg.selectionLimit = 1
            let p = PHPickerViewController(configuration: cfg)
            p.delegate = self
            present(p, animated: true)
        } else {
            let p = UIImagePickerController()
            p.sourceType = .photoLibrary
            p.delegate = self
            present(p, animated: true)
        }
    }

    private func handle(image: UIImage) {
        guard let text = QRImageReader.read(image) else {
            showError("这张图里没找到二维码，换一张或截得更清楚些")
            return
        }
        decode(text, source: "相册导入")
    }

    func decode(_ text: String, source: String) {
        do {
            show(try DongfengDecoder.compute(text), from: source)
        } catch {
            showError((error as? DongfengDecoder.Error)?.errorDescription ?? error.localizedDescription)
        }
    }

    private enum Tone { case gray, green }
    private func hint(_ tone: Tone, _ t: String) {
        hintLabel.textColor = tone == .green ? .systemGreen : .secondaryLabel
        hintLabel.text = t
    }
}

// MARK: - 相册导入

extension HomeViewController: UIImagePickerControllerDelegate, UINavigationControllerDelegate {
    public func imagePickerController(_ picker: UIImagePickerController,
                                      didFinishPickingMediaWithInfo info: [UIImagePickerController.InfoKey: Any]) {
        picker.dismiss(animated: true)
        if let im = info[.originalImage] as? UIImage { handle(image: im) }
    }

    public func imagePickerControllerDidCancel(_ picker: UIImagePickerController) {
        picker.dismiss(animated: true)
    }
}

@available(iOS 14.0, *)
extension HomeViewController: PHPickerViewControllerDelegate {
    public func picker(_ picker: PHPickerViewController, didFinishPicking results: [PHPickerResult]) {
        picker.dismiss(animated: true)
        guard let provider = results.first?.itemProvider else { return }
        if provider.canLoadObject(ofClass: UIImage.self) {
            provider.loadObject(ofClass: UIImage.self) { [weak self] obj, _ in
                DispatchQueue.main.async {
                    guard let self = self, let im = obj as? UIImage else { return }
                    self.handle(image: im)
                }
            }
        }
    }
}

/// 从一张图里解出二维码原文：iOS 16+ 走 Vision（支持 microQR），否则走 CIDetector。
enum QRImageReader {
    static func read(_ image: UIImage) -> String? {
        if #available(iOS 16.0, *) {
            if let s = vision(image) { return s }
        }
        return cidetector(image)
    }

    @available(iOS 16.0, *)
    private static func vision(_ image: UIImage) -> String? {
        guard let cg = image.cgImage else { return nil }
        var out: String?
        let req = VNDetectBarcodesRequest { r, _ in
            let best = (r.results as? [VNBarcodeObservation])?
                .filter { $0.symbology == .qr || $0.symbology == .microQR }
                .max { ($0.boundingBox.width * $0.boundingBox.height) < ($1.boundingBox.width * $1.boundingBox.height) }
            out = best?.payloadStringValue
        }
        req.symbologies = [.qr, .microQR]
        let handler = VNImageRequestHandler(cgImage: cg, orientation: CGImagePropertyOrientation(image.imageOrientation), options: [:])
        try? handler.perform([req])
        return out
    }

    private static func cidetector(_ image: UIImage) -> String? {
        guard let ci = CIImage(image: image),
              let det = CIDetector(ofType: CIDetectorTypeQRCode, context: nil,
                                   options: [CIDetectorAccuracy: CIDetectorAccuracyHigh]) else { return nil }
        let feats = det.features(in: ci, options: [CIDetectorImageOrientation: exif(image.imageOrientation)])
        return (feats.compactMap { ($0 as? CIQRCodeFeature)?.messageString })
            .max { $0.count < $1.count }
    }

    private static func exif(_ o: UIImage.Orientation) -> Int {
        switch o {
        case .up: return 1
        case .right: return 6
        case .down: return 3
        case .left: return 8
        default: return 1
        }
    }
}

private extension CGImagePropertyOrientation {
    init(_ o: UIImage.Orientation) {
        switch o {
        case .up: self = .up
        case .down: self = .down
        case .left: self = .left
        case .right: self = .right
        case .upMirrored: self = .upMirrored
        case .downMirrored: self = .downMirrored
        case .leftMirrored: self = .leftMirrored
        case .rightMirrored: self = .rightMirrored
        @unknown default: self = .up
        }
    }
}
