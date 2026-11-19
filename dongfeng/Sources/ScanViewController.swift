import UIKit
import AVFoundation

final class ScanViewController: UIViewController {

    // MARK: - 状态

    private let sessionQueue = DispatchQueue(label: "df.decoder.session")
    private let session = AVCaptureSession()
    private var cameraReady = false
    private var lastPayload = ""

    // MARK: - 视图

    private let scroll = UIScrollView()
    private let content = UIView()

    private let cameraView = UIView()
    private var previewLayer: AVCaptureVideoPreviewLayer?
    private let cameraHint = UILabel()

    private let inputField = UITextField()
    private let calcButton = UIButton(type: .system)
    private let statusLabel = UILabel()

    private let codeValue = UILabel()
    private let pwdValue = UILabel()
    private let copyPwdButton = UIButton(type: .system)
    private let copyCodeButton = UIButton(type: .system)
    private let noteLabel = UILabel()

    private let metadataOutput: AVCaptureMetadataOutput = {
        let o = AVCaptureMetadataOutput()
        return o
    }()

    // MARK: - 生命周期

    override func viewDidLoad() {
        super.viewDidLoad()
        view.backgroundColor = .systemGroupedBackground
        buildUI()
        AVCaptureDevice.requestAccess(for: .video) { [weak self] granted in
            guard let self = self else { return }
            DispatchQueue.main.async {
                if !granted {
                    self.cameraHint.text = "未授权相机，请在设置里打开；可继续手动粘贴"
                }
            }
            self.sessionQueue.async { self.setupSession() }
        }
    }

    override func viewWillAppear(_ animated: Bool) {
        super.viewWillAppear(animated)
        sessionQueue.async { [weak self] in
            guard let self = self else { return }
            if self.cameraReady && !self.session.isRunning { self.session.startRunning() }
        }
    }

    override func viewWillDisappear(_ animated: Bool) {
        super.viewWillDisappear(animated)
        sessionQueue.async { [weak self] in
            guard let self = self else { return }
            if self.session.isRunning { self.session.stopRunning() }
        }
    }

    override func viewDidLayoutSubviews() {
        super.viewDidLayoutSubviews()
        previewLayer?.frame = cameraView.bounds
        if let connection = previewLayer?.connection, connection.isVideoOrientationSupported {
            connection.videoOrientation = .portrait
        }
    }

    // MARK: - 界面

    private func buildUI() {
        scroll.translatesAutoresizingMaskIntoConstraints = false
        scroll.keyboardDismissMode = .onDrag
        view.addSubview(scroll)

        content.translatesAutoresizingMaskIntoConstraints = false
        scroll.addSubview(content)

        let g = view.safeAreaLayoutGuide
        NSLayoutConstraint.activate([
            scroll.topAnchor.constraint(equalTo: g.topAnchor),
            scroll.leadingAnchor.constraint(equalTo: view.leadingAnchor),
            scroll.trailingAnchor.constraint(equalTo: view.trailingAnchor),
            scroll.bottomAnchor.constraint(equalTo: g.bottomAnchor),

            content.topAnchor.constraint(equalTo: scroll.contentLayoutGuide.topAnchor),
            content.leadingAnchor.constraint(equalTo: scroll.contentLayoutGuide.leadingAnchor),
            content.trailingAnchor.constraint(equalTo: scroll.contentLayoutGuide.trailingAnchor),
            content.bottomAnchor.constraint(equalTo: scroll.contentLayoutGuide.bottomAnchor),
            content.widthAnchor.constraint(equalTo: scroll.frameLayoutGuide.widthAnchor),
        ])

        // 相机预览
        cameraView.backgroundColor = .black
        cameraView.layer.cornerRadius = 14
        cameraView.clipsToBounds = true
        cameraView.translatesAutoresizingMaskIntoConstraints = false
        content.addSubview(cameraView)

        let preview = AVCaptureVideoPreviewLayer(session: session)
        preview.videoGravity = .resizeAspectFill
        cameraView.layer.addSublayer(preview)
        previewLayer = preview

        cameraHint.text = "对准车机弹窗上的二维码，自动计算"
        cameraHint.textColor = .white
        cameraHint.font = .systemFont(ofSize: 13)
        cameraHint.textAlignment = .center
        cameraHint.backgroundColor = UIColor.black.withAlphaComponent(0.45)
        cameraHint.translatesAutoresizingMaskIntoConstraints = false
        cameraView.addSubview(cameraHint)

        // 手动输入
        inputField.placeholder = "手动粘贴：整段 JSON 或 content 里的 base64"
        inputField.borderStyle = .roundedRect
        inputField.font = .systemFont(ofSize: 14)
        inputField.autocorrectionType = .no
        inputField.autocapitalizationType = .none
        inputField.clearButtonMode = .whileEditing
        inputField.returnKeyType = .go
        inputField.delegate = self
        inputField.addTarget(self, action: #selector(onCalc), for: .editingDidEndOnExit)
        inputField.translatesAutoresizingMaskIntoConstraints = false
        content.addSubview(inputField)

        calcButton.setTitle("计算", for: .normal)
        calcButton.titleLabel?.font = .boldSystemFont(ofSize: 17)
        calcButton.backgroundColor = .systemBlue
        calcButton.setTitleColor(.white, for: .normal)
        calcButton.layer.cornerRadius = 10
        calcButton.addTarget(self, action: #selector(onCalc), for: .touchUpInside)
        calcButton.translatesAutoresizingMaskIntoConstraints = false
        content.addSubview(calcButton)

        statusLabel.font = .systemFont(ofSize: 13)
        statusLabel.textColor = .systemRed
        statusLabel.numberOfLines = 0
        statusLabel.translatesAutoresizingMaskIntoConstraints = false
        content.addSubview(statusLabel)

        // 结果卡片
        let card = UIView()
        card.backgroundColor = .secondarySystemGroupedBackground
        card.layer.cornerRadius = 14
        card.translatesAutoresizingMaskIntoConstraints = false
        content.addSubview(card)

        codeValue.font = .monospacedSystemFont(ofSize: 22, weight: .medium)
        codeValue.textColor = .label
        codeValue.adjustsFontSizeToFitWidth = true
        codeValue.text = "——"

        pwdValue.font = .monospacedSystemFont(ofSize: 30, weight: .bold)
        pwdValue.textColor = .label
        pwdValue.adjustsFontSizeToFitWidth = true
        pwdValue.text = "——"

        let codeTitle = rowTitle("随机码（QR 明文）")
        let pwdTitle = rowTitle("应输密码（每位 +2）")
        [codeTitle, pwdTitle, codeValue, pwdValue].forEach { card.addSubview($0) }

        copyPwdButton.setTitle("复制密码", for: .normal)
        copyPwdButton.titleLabel?.font = .boldSystemFont(ofSize: 17)
        copyPwdButton.backgroundColor = .systemGreen
        copyPwdButton.setTitleColor(.white, for: .normal)
        copyPwdButton.layer.cornerRadius = 10
        copyPwdButton.addTarget(self, action: #selector(onCopyPwd), for: .touchUpInside)
        copyPwdButton.translatesAutoresizingMaskIntoConstraints = false
        content.addSubview(copyPwdButton)

        copyCodeButton.setTitle("复制随机码", for: .normal)
        copyCodeButton.titleLabel?.font = .systemFont(ofSize: 15)
        copyCodeButton.backgroundColor = .secondarySystemGroupedBackground
        copyCodeButton.setTitleColor(.label, for: .normal)
        copyCodeButton.layer.cornerRadius = 10
        copyCodeButton.addTarget(self, action: #selector(onCopyCode), for: .touchUpInside)
        copyCodeButton.translatesAutoresizingMaskIntoConstraints = false
        content.addSubview(copyCodeButton)

        noteLabel.text = "同一弹窗期间扫一次就够，关闭重开不换码；工程模式 Activity 重建后需重扫重算。\n失败次数会累计、按日重置——输错一次就停手。本工具纯离线，不联网、不读写车机。"
        noteLabel.font = .systemFont(ofSize: 12)
        noteLabel.textColor = .secondaryLabel
        noteLabel.numberOfLines = 0
        noteLabel.translatesAutoresizingMaskIntoConstraints = false
        content.addSubview(noteLabel)

        NSLayoutConstraint.activate([
            cameraView.topAnchor.constraint(equalTo: content.topAnchor, constant: 8),
            cameraView.leadingAnchor.constraint(equalTo: content.leadingAnchor, constant: 16),
            cameraView.trailingAnchor.constraint(equalTo: content.trailingAnchor, constant: -16),
            cameraView.heightAnchor.constraint(equalTo: cameraView.widthAnchor, multiplier: 0.6),

            cameraHint.leadingAnchor.constraint(equalTo: cameraView.leadingAnchor),
            cameraHint.trailingAnchor.constraint(equalTo: cameraView.trailingAnchor),
            cameraHint.bottomAnchor.constraint(equalTo: cameraView.bottomAnchor),
            cameraHint.heightAnchor.constraint(equalToConstant: 30),

            inputField.topAnchor.constraint(equalTo: cameraView.bottomAnchor, constant: 12),
            inputField.leadingAnchor.constraint(equalTo: content.leadingAnchor, constant: 16),
            inputField.trailingAnchor.constraint(equalTo: content.trailingAnchor, constant: -16),
            inputField.heightAnchor.constraint(equalToConstant: 40),

            calcButton.topAnchor.constraint(equalTo: inputField.bottomAnchor, constant: 10),
            calcButton.leadingAnchor.constraint(equalTo: content.leadingAnchor, constant: 16),
            calcButton.trailingAnchor.constraint(equalTo: content.trailingAnchor, constant: -16),
            calcButton.heightAnchor.constraint(equalToConstant: 44),

            statusLabel.topAnchor.constraint(equalTo: calcButton.bottomAnchor, constant: 8),
            statusLabel.leadingAnchor.constraint(equalTo: content.leadingAnchor, constant: 16),
            statusLabel.trailingAnchor.constraint(equalTo: content.trailingAnchor, constant: -16),

            card.topAnchor.constraint(equalTo: statusLabel.bottomAnchor, constant: 8),
            card.leadingAnchor.constraint(equalTo: content.leadingAnchor, constant: 16),
            card.trailingAnchor.constraint(equalTo: content.trailingAnchor, constant: -16),
            card.bottomAnchor.constraint(equalTo: pwdValue.bottomAnchor, constant: 14),

            codeTitle.topAnchor.constraint(equalTo: card.topAnchor, constant: 12),
            codeTitle.leadingAnchor.constraint(equalTo: card.leadingAnchor, constant: 14),

            codeValue.topAnchor.constraint(equalTo: codeTitle.bottomAnchor, constant: 2),
            codeValue.leadingAnchor.constraint(equalTo: card.leadingAnchor, constant: 14),
            codeValue.trailingAnchor.constraint(equalTo: card.trailingAnchor, constant: -14),

            pwdTitle.topAnchor.constraint(equalTo: codeValue.bottomAnchor, constant: 14),
            pwdTitle.leadingAnchor.constraint(equalTo: card.leadingAnchor, constant: 14),

            pwdValue.topAnchor.constraint(equalTo: pwdTitle.bottomAnchor, constant: 2),
            pwdValue.leadingAnchor.constraint(equalTo: card.leadingAnchor, constant: 14),
            pwdValue.trailingAnchor.constraint(equalTo: card.trailingAnchor, constant: -14),

            copyPwdButton.topAnchor.constraint(equalTo: card.bottomAnchor, constant: 12),
            copyPwdButton.leadingAnchor.constraint(equalTo: content.leadingAnchor, constant: 16),
            copyPwdButton.trailingAnchor.constraint(equalTo: content.trailingAnchor, constant: -16),
            copyPwdButton.heightAnchor.constraint(equalToConstant: 48),

            copyCodeButton.topAnchor.constraint(equalTo: copyPwdButton.bottomAnchor, constant: 8),
            copyCodeButton.leadingAnchor.constraint(equalTo: content.leadingAnchor, constant: 16),
            copyCodeButton.trailingAnchor.constraint(equalTo: content.trailingAnchor, constant: -16),
            copyCodeButton.heightAnchor.constraint(equalToConstant: 40),

            noteLabel.topAnchor.constraint(equalTo: copyCodeButton.bottomAnchor, constant: 12),
            noteLabel.leadingAnchor.constraint(equalTo: content.leadingAnchor, constant: 16),
            noteLabel.trailingAnchor.constraint(equalTo: content.trailingAnchor, constant: -16),
            noteLabel.bottomAnchor.constraint(equalTo: content.bottomAnchor, constant: -20),
        ])
    }

    private func rowTitle(_ t: String) -> UILabel {
        let l = UILabel()
        l.text = t
        l.font = .systemFont(ofSize: 12)
        l.textColor = .secondaryLabel
        l.translatesAutoresizingMaskIntoConstraints = false
        return l
    }

    // MARK: - 相机会话

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
        DispatchQueue.main.async { [weak self] in
            guard let self = self else { return }
            if !self.cameraReady && self.cameraHint.text?.contains("未授权") != true {
                self.cameraHint.text = "相机不可用，请用下方手动粘贴"
            }
            if self.cameraReady { self.session.startRunning() }
        }
    }

    // MARK: - 计算

    @objc private func onCalc() {
        view.endEditing(true)
        apply(inputField.text ?? "")
    }

    private func apply(_ payload: String) {
        let trimmed = payload.trimmingCharacters(in: .whitespacesAndNewlines)
        guard !trimmed.isEmpty else { return }
        do {
            let r = try DongfengDecoder.compute(trimmed)
            codeValue.text = r.code
            pwdValue.text = r.password
            statusLabel.text = ""
            if inputField.text?.trimmingCharacters(in: .whitespacesAndNewlines) != trimmed {
                inputField.text = trimmed
            }
            UIImpactFeedbackGenerator(style: .medium).impactOccurred()
        } catch {
            codeValue.text = "——"
            pwdValue.text = "——"
            statusLabel.text = (error as? DongfengDecoder.Error)?.errorDescription
                ?? error.localizedDescription
            UINotificationFeedbackGenerator().notificationOccurred(.error)
        }
    }

    // MARK: - 复制

    @objc private func onCopyPwd() {
        let s = pwdValue.text ?? ""
        guard s != "——", !s.isEmpty else {
            statusLabel.text = "还没有可复制的密码"
            return
        }
        UIPasteboard.general.string = s
        flash(copyPwdButton, "已复制 \(s)")
    }

    @objc private func onCopyCode() {
        let s = codeValue.text ?? ""
        guard s != "——", !s.isEmpty else { return }
        UIPasteboard.general.string = s
        flash(copyCodeButton, "已复制随机码")
    }

    private func flash(_ button: UIButton, _ text: String) {
        let old = button.title(for: .normal)
        button.setTitle(text, for: .normal)
        button.isEnabled = false
        DispatchQueue.main.asyncAfter(deadline: .now() + 1.2) {
            button.setTitle(old, for: .normal)
            button.isEnabled = true
        }
    }
}

// MARK: - 扫码回调

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

extension ScanViewController: UITextFieldDelegate {
    func textFieldShouldReturn(_ textField: UITextField) -> Bool {
        onCalc()
        return true
    }
}
