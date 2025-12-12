## Phishing Detection System using Machine Learning and Deep Learning
The Phishing Detection System is designed to intelligently identify phishing emails and malicious URLs in real time. Traditional phishing detection methods rely heavily on blacklists and heuristic rules, which fail against modern and evolving phishing attacks. This project introduces a dual-model system using a CNN for email content analysis and an XGBoost model for URL classification, enhancing accuracy, scalability, and cyber protection.

## About
<!--Detailed Description about the project-->
The Phishing Detection System is a machine learning and deep learning–based security tool that detects phishing attempts through email content and URL pattern analysis. Phishing attacks are increasing rapidly, and conventional security methods cannot detect newly generated (zero-day) phishing links or sophisticated social engineering emails.

This project aims to overcome these challenges by integrating:

A CNN-based email classification model to detect suspicious patterns in email text

An XGBoost-based URL classifier that analyzes domain and lexical features

A Streamlit frontend for user interaction

A FastAPI/Flask backend that handles predictions in real time

The system provides a fast, accurate, and intelligent phishing detection mechanism to protect users from online threats.

## Features
<!--List the features of the project as shown below-->
- Dual-engine phishing detection (Email + URL)
- Uses advanced CNN for email analysis
- Uses XGBoost for URL classification
- Real-time predictions with confidence score
- Lightweight deployment using Streamlit + FastAPI/Flask
- High scalability and low latency
- JSON-based communication between frontend and backend
- Secure input handling and user-friendly interface


## Requirements
<!--List the requirements of the project as shown below-->
- Operating System: Requires a 64-bit OS (Windows 10 / 11 or Ubuntu) for compatibility with machine learning and deep learning frameworks.
- Development Environment: Python 3.8 or later is required for building and running the Phishing Detection System.
- Deep Learning / Machine Learning Frameworks: TensorFlow/Keras for training and running the CNN-based email analysis model. XGBoost for URL classification using feature-based methods.
- Data Processing & Feature Extraction Libraries: Pandas and NumPy for dataset handling, preprocessing, and feature extraction. Scikit-learn for data splitting, preprocessing pipelines, and evaluation metrics.
- Networking & API Frameworks: FastAPI or Flask for backend API development to handle email/URL predictions.
- User Interface Framework: Streamlit for building an interactive and user-friendly frontend interface.
- Version Control: Git for code management, version tracking, and collaborative development.
- IDE: VSCode or PyCharm as the Integrated Development Environment for coding, debugging, and project structuring.
- Additional Dependencies: Includes JSON, Joblib/Pickle (for saving models), Requests (API calls), and Matplotlib/Seaborn (optional for visualization tasks).


## System Architecture
<!--Embed the system architecture diagram as shown below-->

<img width="542" height="479" alt="image" src="https://github.com/user-attachments/assets/fb25ee1f-4a3d-4cc0-91d0-04178fd8fcbb" />


## Output

<!--Embed the Output picture at respective places as shown below as shown below-->
#### Output1 - Name of the output

<img width="1919" height="767" alt="image" src="https://github.com/user-attachments/assets/8f232d5d-edac-422e-807c-d54af8ef77a2" />

#### Output2 - Name of the output
<img width="1919" height="861" alt="image" src="https://github.com/user-attachments/assets/b32e45fd-46d4-41cd-aa94-4821060a7c20" />

Detection Accuracy:

CNN Email Model Accuracy: ~95%

XGBoost URL Model Accuracy: ~96% Note: These metrics can be customized based on your actual performance evaluations.


## Results and Impact
<!--Give the results and impact as shown below-->
The Phishing Detection System successfully enhances cybersecurity by providing an intelligent, adaptive approach to phishing detection. Unlike traditional blacklist-based methods, the dual-model architecture can:

- Detect zero-day phishing websites
- Identify suspicious email content
- Reduce false positives and false negatives
- Provide real-time detection with high accuracy

This project contributes to safer email communication, secure browsing, and a significant reduction in phishing-based cyberattacks. It also establishes a strong foundation for future development in AI-driven cybersecurity tools.

## Articles published / References
1. J. Kumar, B. Rajendran, A. Santhanavijayan, and B. S. Bindhumadhava, “Phishing Website Classification and Detection Using Machine Learning,” ICCCI, 2020.
2. F. Salahdine, Z. El Mrabet, N. Kaabouch, “Phishing Attacks Detection: A Machine-Learning Based Approach.”
3. A. Dawabsheh et al., “An Enhanced Phishing Detection Tool Using Deep Learning From URL,” SmartNets, 2022.
4. V. Yazhmozhi and B. Janet, “Anti-phishing System using LSTM and CNN,” INOCON, 2020.
5. A. Kovač, I. Dunder, and S. Seljan, “An overview of ML algorithms for detecting phishing attacks,” MIPRO, 2022.




