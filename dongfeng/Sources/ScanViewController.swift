import UIKit
import AVFoundation

/// 扫码页：整屏摄像头，识别到就自动算，算完回主界面。
/// 左边缘向右滑 = 返回主界面。
final class ScanViewController: UIViewController {

    var onResult: ((DongfengDecoder.Output) -> Void)?

    private let sessionQueue = DispatchQueue(label: "df.decoder.session")
    private let session = AVCaptureSession()
    private var cameraReady = false
    private var lastPayload = ""

    private let cameraView = UIView()
    private var previewLayer: AVCaptureVideoPreviewLayer?
    private let statusLabel = UILabel()
    private let metadataOutput: AVCaptureMetadataOutput = AVCaptureMetadataOutput()

    override func viewDidLoad() {
        super.viewDidLoad()
        view.backgroundColor = .black

        cameraView.backgroundColor = .black
        cameraView.translatesAutoresizingMaskIntoConstraints = false
        view.addSubview(cameraView)

        statusLabel.textColor = .white
        statusLabel.font = .systemFont(ofSize: 15, weight: .medium)
        statusLabel.textAlignment = .center
        statusLabel.numberOfLines = 2
        statusLabel.translatesAutoresizingMaskIntoConstraints = false
        view.addSubview(statusLabel)

        let g = view.safeAreaLayoutGuide
        NSLayoutConstraint.activate([
            cameraView.topAnchor.constraint(equalTo: view.topAnchor),
            cameraView.leadingAnchor.constraint(equalTo: view.leadingAnchor),
            cameraView.trailingAnchor.constraint(equalTo: view.trailingAnchor),
            cameraView.bottomAnchor.constraint(equalTo: view.bottomAnchor),

            statusLabel.bottomAnchor.constraint(equalTo: g.bottomAnchor, constant: -16),
            statusLabel.leadingAnchor.constraint(equalTo: view.leadingAnchor, constant: 16),
            statusLabel.trailingAnchor.constraint(equalTo: view.trailingAnchor, constant: -16),
        ])

        let preview = AVCaptureVideoPreviewLayer(session: session)
        preview.videoGravity = .resizeAspectFill   // 铺满整屏，不留黑边
        cameraView.layer.addSublayer(preview)
        previewLayer = preview

        status("对准车机弹窗上的二维码 · 左边缘右滑返回")

        let back = UIScreenEdgePanGestureRecognizer(target: self, action: #selector(onEdgeBack(_:)))
        back.edges = .left
        view.addGestureRecognizer(back)

        AVCaptureDevice.requestAccess(for: .video) { [weak self] granted in
            guard let self = self else { return }
            if !granted {
                DispatchQueue.main.async { self.status("未授权相机，去「设置 → 奕派解码器」里打开") }
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
        // 只认屏幕上看得见的那块区域，避免解到画面外/别的二维码
        if let p = previewLayer, cameraReady {
            metadataOutput.rectOfInterest = p.metadataOutputRectConverted(fromLayerRect: cameraView.bounds)
        }
    }

    @objc private func onEdgeBack(_ gr: UIScreenEdgePanGestureRecognizer) {
        guard gr.state == .ended, gr.translation(in: view).x > 60 else { return }
        dismiss(animated: true)
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
            DispatchQueue.main.async { [weak self] in self?.status("相机不可用") }
        }
        if hasInput { session.startRunning() }
    }

    private func status(_ t: String) {
        statusLabel.textColor = .white
        statusLabel.text = t
    }

    private func fail(_ t: String) {
        statusLabel.textColor = .systemRed
        statusLabel.text = t
        UINotificationFeedbackGenerator().notificationOccurred(.error)
    }
}

extension ScanViewController: AVCaptureMetadataOutputObjectsDelegate {
    func metadataOutput(_ output: AVCaptureMetadataOutput,
                        didOutput metadataObjects: [AVMetadataObject],
                        from connection: AVCaptureConnection) {
        // 画面里可能有多个码，取最大的那个
        guard let obj = metadataObjects.compactMap({ $0 as? AVMetadataMachineReadableCodeObject })
                .max(by: { $0.bounds.width * $0.bounds.height < $1.bounds.width * $1.bounds.height }),
              let text = obj.stringValue, !text.isEmpty else { return }
        if text == lastPayload { return }
        lastPayload = text

        do {
            let r = try DongfengDecoder.compute(text)
            UIImpactFeedbackGenerator(style: .medium).impactOccurred()
            dismiss(animated: true) { [weak self] in self?.onResult?(r) }
        } catch {
            fail((error as? DongfengDecoder.Error)?.errorDescription ?? error.localizedDescription)
        }
    }
}
