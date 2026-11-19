import UIKit
import AVFoundation

/// 极简界面：顶部标题、中间摄像头全屏、底部只算出来的密码。
final class ScanViewController: UIViewController {

    private let sessionQueue = DispatchQueue(label: "df.decoder.session")
    private let session = AVCaptureSession()
    private var cameraReady = false
    private var lastPayload = ""
    private var password = ""

    private let titleLabel = UILabel()
    private let cameraView = UIView()
    private var previewLayer: AVCaptureVideoPreviewLayer?
    private let resultLabel = UILabel()
    private let hintLabel = UILabel()

    private let metadataOutput: AVCaptureMetadataOutput = AVCaptureMetadataOutput()

    override func viewDidLoad() {
        super.viewDidLoad()
        view.backgroundColor = .black
        buildUI()
        AVCaptureDevice.requestAccess(for: .video) { [weak self] granted in
            guard let self = self else { return }
            if !granted {
                DispatchQueue.main.async { self.hint("未授权相机，去「设置 → 奕派解码器」里打开") }
            }
            self.sessionQueue.async { self.setupSession() }
        }
    }

    override func viewWillAppear(_ animated: Bool) {
        super.viewWillAppear(animated)
        sessionQueue.async { [weak self] in
            guard let self = self, self.cameraReady, !self.session.isRunning else { return }
            self.session.startRunning()
        }
    }

    override func viewWillDisappear(_ animated: Bool) {
        super.viewWillDisappear(animated)
        sessionQueue.async { [weak self] in
            guard let self = self, self.session.isRunning else { return }
            self.session.stopRunning()
        }
    }

    override func viewDidLayoutSubviews() {
        super.viewDidLayoutSubviews()
        previewLayer?.frame = cameraView.bounds
        if let c = previewLayer?.connection, c.isVideoOrientationSupported {
            c.videoOrientation = .portrait
        }
    }

    private func buildUI() {
        titleLabel.text = "奕派解码器"
        titleLabel.textColor = .white
        titleLabel.font = .systemFont(ofSize: 20, weight: .semibold)
        titleLabel.textAlignment = .center
        titleLabel.translatesAutoresizingMaskIntoConstraints = false
        view.addSubview(titleLabel)

        cameraView.backgroundColor = .black
        cameraView.translatesAutoresizingMaskIntoConstraints = false
        view.addSubview(cameraView)

        let preview = AVCaptureVideoPreviewLayer(session: session)
        preview.videoGravity = .resizeAspectFit
        cameraView.layer.addSublayer(preview)
        previewLayer = preview

        resultLabel.text = "——"
        resultLabel.textColor = .white
        resultLabel.font = .monospacedSystemFont(ofSize: 52, weight: .bold)
        resultLabel.textAlignment = .center
        resultLabel.adjustsFontSizeToFitWidth = true
        resultLabel.isUserInteractionEnabled = true
        resultLabel.translatesAutoresizingMaskIntoConstraints = false
        view.addSubview(resultLabel)
        resultLabel.addGestureRecognizer(UITapGestureRecognizer(target: self, action: #selector(onCopy)))

        hintLabel.textColor = .secondaryLabel
        hintLabel.font = .systemFont(ofSize: 13)
        hintLabel.textAlignment = .center
        hintLabel.numberOfLines = 2
        hintLabel.translatesAutoresizingMaskIntoConstraints = false
        hintLabel.text = "对准车机弹窗上的二维码，自动算出密码"
        view.addSubview(hintLabel)

        let g = view.safeAreaLayoutGuide
        NSLayoutConstraint.activate([
            titleLabel.topAnchor.constraint(equalTo: g.topAnchor, constant: 6),
            titleLabel.leadingAnchor.constraint(equalTo: view.leadingAnchor, constant: 12),
            titleLabel.trailingAnchor.constraint(equalTo: view.trailingAnchor, constant: -12),

            cameraView.topAnchor.constraint(equalTo: titleLabel.bottomAnchor, constant: 8),
            cameraView.leadingAnchor.constraint(equalTo: view.leadingAnchor),
            cameraView.trailingAnchor.constraint(equalTo: view.trailingAnchor),
            cameraView.bottomAnchor.constraint(equalTo: resultLabel.topAnchor, constant: -8),

            resultLabel.bottomAnchor.constraint(equalTo: hintLabel.topAnchor, constant: -6),
            resultLabel.leadingAnchor.constraint(equalTo: view.leadingAnchor, constant: 16),
            resultLabel.trailingAnchor.constraint(equalTo: view.trailingAnchor, constant: -16),
            resultLabel.heightAnchor.constraint(equalToConstant: 68),

            hintLabel.bottomAnchor.constraint(equalTo: g.bottomAnchor, constant: -8),
            hintLabel.leadingAnchor.constraint(equalTo: view.leadingAnchor, constant: 16),
            hintLabel.trailingAnchor.constraint(equalTo: view.trailingAnchor, constant: -16),
        ])
    }

    // MARK: - 相机

    private func setupSession() {
        guard AVCaptureDevice.default(for: .video) != nil else { return }
        session.beginConfiguration()
        session.sessionPreset = .high

        var hasInput = false
        if let device = AVCaptureDevice.default(for: .video),
           let input = try? AVCaptureDeviceInput(device: device),
           session.canAddInput(input) {
            session.addInput(input)
            hasInput = true
        }
        if hasInput, session.canAddOutput(metadataOutput) {
            session.addOutput(metadataOutput)
            metadataOutput.setMetadataObjectsDelegate(self, queue: .main)
            var types: [AVMetadataObject.ObjectType] = [.qr]
            if #available(iOS 15.4, *), metadataOutput.availableMetadataObjectTypes.contains(.microQR) {
                types.append(.microQR)
            }
            metadataOutput.metadataObjectTypes = types
        }
        session.commitConfiguration()

        cameraReady = hasInput
        if !hasInput {
            DispatchQueue.main.async { [weak self] in self?.hint("相机不可用") }
        }
        if hasInput { session.startRunning() }
    }

    // MARK: - 计算

    private func apply(_ payload: String) {
        do {
            let r = try DongfengDecoder.compute(payload)
            password = r.password
            resultLabel.textColor = .white
            resultLabel.text = r.password
            hintLabel.text = ""
            UIImpactFeedbackGenerator(style: .medium).impactOccurred()
        } catch {
            password = ""
            resultLabel.text = "——"
            resultLabel.textColor = .secondaryLabel
            hint((error as? DongfengDecoder.Error)?.errorDescription ?? error.localizedDescription)
            UINotificationFeedbackGenerator().notificationOccurred(.error)
        }
    }

    @objc private func onCopy() {
        guard !password.isEmpty else { return }
        UIPasteboard.general.string = password
        hintLabel.textColor = .systemGreen
        hintLabel.text = "已复制 \(password)"
        hintLabel.isHidden = false
        DispatchQueue.main.asyncAfter(deadline: .now() + 1.4) { [weak self] in
            guard let self = self, self.hintLabel.textColor == .systemGreen else { return }
            self.hintLabel.text = ""
            self.hintLabel.textColor = .secondaryLabel
        }
    }

    private func hint(_ t: String) {
        hintLabel.textColor = .secondaryLabel
        hintLabel.text = t
    }
}

extension ScanViewController: AVCaptureMetadataOutputObjectsDelegate {
    func metadataOutput(_ output: AVCaptureMetadataOutput,
                        didOutput metadataObjects: [AVMetadataObject],
                        from connection: AVCaptureConnection) {
        guard let obj = metadataObjects.first as? AVMetadataMachineReadableCodeObject,
              let text = obj.stringValue, text != lastPayload else { return }
        lastPayload = text
        apply(text)
    }
}
