import React, { useState, useRef, useEffect, useCallback } from 'react';
import axios from 'axios';
import { jsPDF } from 'jspdf';
import html2canvas from 'html2canvas';
import htmlToDocx from 'html-to-docx';
import { saveAs } from 'file-saver';
import './App.css';

// Icon imports
import { 
  FaGithub, FaLinkedin, FaGlobe, FaSave, 
  FaArrowLeft, FaArrowRight, FaEye, FaEdit,
  FaUser, FaLock, FaSignOutAlt, FaUserPlus,
  FaHome, FaFilePdf, FaDatabase, FaSync,
  FaChevronRight, FaChevronLeft, FaBars, FaTimes,
  FaDownload, FaCog, FaCheck, FaPlus, FaMinus,
  FaSearch, FaTrash, FaEyeSlash, FaExclamationTriangle,
  FaInfoCircle, FaShieldAlt, FaPlug, FaNetworkWired,
  FaKey, FaEnvelope, FaDatabase as FaDb,
  FaBriefcase, FaGraduationCap, FaCode, FaTools,
  FaMapMarkerAlt, FaPhone, FaCalendarAlt,
  FaFileWord, FaFileImage, FaFileAlt
} from 'react-icons/fa';

// Helper function for email validation
const isValidEmail = (email) => {
  if (!email) return false;
  const emailRegex = /^[^\s@]+@[^\s@]+\.[^\s@]+$/;
  return emailRegex.test(email.trim());
};

// Helper function to debounce API calls
const debounce = (func, delay) => {
  let timeoutId;
  return (...args) => {
    clearTimeout(timeoutId);
    timeoutId = setTimeout(() => func(...args), delay);
  };
};

const App = () => {
  const resumeRef = useRef();
  const [isAuthenticated, setIsAuthenticated] = useState(false);
  const [showLogin, setShowLogin] = useState(true);
  const [formStep, setFormStep] = useState(1);
  const [isLoading, setIsLoading] = useState(false);
  const [isSaving, setIsSaving] = useState(false);
  const [apiMessage, setApiMessage] = useState('');
  const [apiError, setApiError] = useState('');
  const [isMobileMenuOpen, setIsMobileMenuOpen] = useState(false);
  const [isPreviewVisible, setIsPreviewVisible] = useState(true);
  const [isApiLoading, setIsApiLoading] = useState(false);
  const [connectionStatus, setConnectionStatus] = useState('checking');
  const [exportProgress, setExportProgress] = useState({ type: '', progress: 0 });
  
  // New states for resume fetching
  const [userEmail, setUserEmail] = useState('');
  const [existingResume, setExistingResume] = useState(null);
  const [isCheckingResume, setIsCheckingResume] = useState(false);
  
  const [loading, setLoading] = useState(false);
  const [notification, setNotification] = useState({ message: '', type: '' });
  
  // Login/Register state
  const [authData, setAuthData] = useState({
    username: '',
    email: '',
    password: '',
    confirmPassword: ''
  });
  const [authError, setAuthError] = useState('');
  
  const [formData, setFormData] = useState({
    fullName: '',
    email: '',
    phone: '',
    address: '',
    personalLinks: { 
      GitHub: '', 
      LinkedIn: '', 
      Portfolio: ''
    },
    summary: '',
    experience: [{ 
      id: Date.now(),
      company: '', 
      position: '',
      type: '', 
      duration: '',
      points: [''] 
    }],
    education: [{ 
      id: Date.now(),
      institution: '', 
      degree: '', 
      score: '', 
      year: '',
      location: ''
    }],
    projects: [{ 
      id: Date.now(),
      name: '', 
      points: [''],
      technologies: ''
    }],
    technicalSkills: {
      languages: '',
      frontEnd: '',
      backEnd: '',
      database: '',
      tools: ''
    }
  });

  // API Configuration
  const API_BASE_URL = 'https://resume-builder-app-1-trx0.onrender.com';
  const LOGIN_URL = `${API_BASE_URL}/api/login`;
  const REGISTER_URL = `${API_BASE_URL}/api/login/register`;
  const CHECK_RESUME_URL = `${API_BASE_URL}/api/resumes/check`;
  const SAVE_RESUME_URL = `${API_BASE_URL}/api/resumes/save`;
  
  // Create axios instance with default config
  const apiClient = axios.create({
    baseURL: API_BASE_URL,
    timeout: 15000,
    headers: {
      'Accept': 'application/json',
      'Content-Type': 'application/json',
    }
  });

  // Enhanced request interceptor
  apiClient.interceptors.request.use(
    config => {
      const user = JSON.parse(localStorage.getItem('resume_builder_user') || '{}');
      if (user.email) {
        config.headers['X-User-Email'] = user.email;
      }
      console.log(`📤 ${config.method.toUpperCase()} ${config.url}`);
      return config;
    },
    error => {
      console.error('❌ Request Error:', error);
      return Promise.reject(error);
    }
  );

  // Enhanced response interceptor
  apiClient.interceptors.response.use(
    response => {
      console.log(`✅ ${response.status}: ${response.config.url}`);
      return response;
    },
    error => {
      if (error.response) {
        console.error('❌ Server Error:', {
          status: error.response.status,
          data: error.response.data,
          url: error.config.url
        });
      } else if (error.request) {
        console.error('❌ No Response:', error.message);
      } else {
        console.error('❌ Request Setup Error:', error.message);
      }
      return Promise.reject(error);
    }
  );

  // Check if user is already logged in
  useEffect(() => {
    const savedUser = localStorage.getItem('resume_builder_user');
    if (savedUser) {
      try {
        const user = JSON.parse(savedUser);
        if (user && user.email) {
          setIsAuthenticated(true);
          setUserEmail(user.email);
        }
      } catch (error) {
        console.error('Error parsing saved user:', error);
        localStorage.removeItem('resume_builder_user');
      }
    }
  }, []);

  // Test backend connection on component mount
  useEffect(() => {
    testBackendConnection();
  }, []);

  // Auto-check for existing resume when user email changes
  useEffect(() => {
    if (isAuthenticated && userEmail && isValidEmail(userEmail)) {
      const timer = setTimeout(() => {
        checkExistingResume(userEmail);
      }, 1000);
      return () => clearTimeout(timer);
    }
  }, [isAuthenticated, userEmail]);

  // Enhanced backend connection test
  const testBackendConnection = async () => {
    setConnectionStatus('checking');
    
    try {
      // Test using the exact same pattern as your curl command
      const response = await fetch(
        `${API_BASE_URL}/api/login?email=mby212001%40gmail.com&password=dummy`,
        {
          method: 'GET',
          headers: { 'Accept': 'application/json' }
        }
      );
      
      console.log('Backend connection test:', {
        status: response.status,
        statusText: response.statusText,
        ok: response.ok
      });
      
      if (response.ok) {
        setConnectionStatus('connected');
        return true;
      } else {
        setConnectionStatus('connected');
        return true;
      }
    } catch (error) {
      console.warn('⚠️ Backend connection failed:', error.message);
      
      setConnectionStatus('disconnected');
      return false;
    }
  };
  // Check for existing resume
  const checkExistingResume = async (email) => {
    if (!email || !isValidEmail(email)) {
      setApiError('❌ Please enter a valid email to check for existing resume');
      setTimeout(() => setApiError(''), 3000);
      return;
    }
    
    if (isApiLoading || isCheckingResume) {
      setApiMessage('⏳ Please wait, another request is in progress...');
      return;
    }
    
    setIsCheckingResume(true);
    setIsApiLoading(true);
    setApiMessage('🔍 Checking for existing resume...');
    
    try {
      const cleanEmail = email.trim();
      
      console.log(`Checking resume for: ${cleanEmail}`);
      
      const response = await apiClient.get('/api/resumes/check', {
        params: {
          email: cleanEmail
        }
      });
      
      if (response.data && (response.data.fullName || response.data.email)) {
        setExistingResume(response.data);
        setApiMessage('📄 Found existing resume! Click "Load Resume" to use it.');
      } else {
        setApiMessage('📝 No existing resume found. Start fresh!');
        setExistingResume(null);
      }
    } catch (error) {
      console.error('Error checking for existing resume:', error);
      
      if (error.code === 'ECONNABORTED') {
        setApiMessage('⚠️ Request timeout. Please check your network connection.');
      } else if (error.response) {
        if (error.response.status === 404) {
          setApiMessage('📝 No existing resume found. Start fresh!');
          setExistingResume(null);
        } else {
          setApiMessage(`⚠️ Server error: ${error.response.status} - ${error.response.data?.message || 'Unknown error'}`);
        }
      } else if (error.request) {
        setApiMessage('⚠️ Could not connect to server. Check if backend is running.');
      } else {
        setApiMessage('⚠️ Error checking for existing resume. Please try again.');
      }
    } finally {
      setIsCheckingResume(false);
      setIsApiLoading(false);
    }
  };

  // Debounced version for typing
  const debouncedCheckResume = useCallback(
    debounce((email) => {
      if (email && isValidEmail(email)) {
        checkExistingResume(email);
      }
    }, 500),
    []
  );

  // Auto-fill form from existing resume data
  const autoFillFormFromExistingResume = useCallback((resumeData) => {
    if (!resumeData) return;
    
    console.log("Auto-filling form with data:", resumeData);
    
    // Basic info
    const updates = {
      fullName: resumeData.fullName || '',
      email: resumeData.email || formData.email || userEmail || '',
      phone: resumeData.phone || '',
      address: resumeData.address || '',
      personalLinks: resumeData.personalLinks || { GitHub: '', LinkedIn: '', Portfolio: '' },
      summary: resumeData.summary || '',
    };
    
    // Education
    if (resumeData.education && resumeData.education.length > 0) {
      updates.education = resumeData.education.map(edu => ({
        id: Date.now() + Math.random(),
        institution: edu.institution || '',
        degree: edu.degree || '',
        score: edu.score || '',
        year: edu.year || '',
        location: edu.location || ''
      }));
    }
    
    // Projects
    if (resumeData.projects && resumeData.projects.length > 0) {
      updates.projects = resumeData.projects.map(proj => ({
        id: Date.now() + Math.random(),
        name: proj.name || '',
        points: proj.description ? [proj.description] : [''],
        technologies: proj.technologies || ''
      }));
    }
    
    // Technical Skills - extract from various sources
    let techSkills = '';
    if (resumeData.technicalSkills) {
      techSkills = resumeData.technicalSkills;
    } else if (resumeData.additionalInfo?.SubjectProficiency) {
      techSkills = resumeData.additionalInfo.SubjectProficiency;
    } else if (resumeData.summary) {
      // Try to extract from summary
      const techKeywords = ['Java', 'Spring', 'React', 'JavaScript', 'Python', 'Node.js', 
                           'MySQL', 'MongoDB', 'AWS', 'Docker', 'Git'];
      const foundSkills = techKeywords.filter(keyword => 
        resumeData.summary.toLowerCase().includes(keyword.toLowerCase())
      );
      techSkills = foundSkills.join(', ');
    }
    
    const skillsArray = techSkills.split(',').map(skill => skill.trim());
    
    updates.technicalSkills = {
      languages: skillsArray[0] || '',
      frontEnd: skillsArray[1] || '',
      backEnd: skillsArray[2] || '',
      database: skillsArray[3] || '',
      tools: skillsArray[4] || ''
    };
    
    setFormData(prev => ({ ...prev, ...updates }));
    
    // Show success message
    setTimeout(() => {
      setApiMessage('✅ Resume data auto-filled! Review and edit as needed.');
    }, 1000);
  }, [formData.email, userEmail]);

  // Load existing resume into form - Manual trigger
  const loadExistingResume = () => {
    if (!existingResume) return;
    
    autoFillFormFromExistingResume(existingResume);
    
    // Also show a manual success message
    setApiMessage('✅ Resume loaded successfully!');
    setTimeout(() => setApiMessage(''), 3000);
  };

  // Clear all form data
  const clearFormData = () => {
    if (window.confirm('Are you sure you want to clear all form data?')) {
      setFormData({
        fullName: '',
        email: userEmail || '',
        phone: '',
        address: '',
        personalLinks: { 
          GitHub: '', 
          LinkedIn: '', 
          Portfolio: ''
        },
        summary: '',
        experience: [{ 
          id: Date.now(),
          company: '', 
          position: '',
          type: '', 
          duration: '',
          points: [''] 
        }],
        education: [{ 
          id: Date.now(),
          institution: '', 
          degree: '', 
          score: '', 
          year: '',
          location: ''
        }],
        projects: [{ 
          id: Date.now(),
          name: '', 
          points: [''],
          technologies: ''
        }],
        technicalSkills: {
          languages: '',
          frontEnd: '',
          backEnd: '',
          database: '',
          tools: ''
        }
      });
      setApiMessage('🧹 Form cleared!');
      setTimeout(() => setApiMessage(''), 3000);
    }
  };

  // Auth handlers
  const handleAuthInput = (e) => {
    const { name, value } = e.target;
    setAuthData(prev => ({
      ...prev,
      [name]: value
    }));
  };

  // UPDATED: Login function using GET with query parameters (matching your curl command)
  const handleLogin = async (e) => {
    e.preventDefault();
    setAuthError('');
    setApiMessage('Logging in...');
    setIsApiLoading(true);

    const userEmail = authData.email.trim();
    const userPassword = authData.password;

    if (!userEmail || !userPassword) {
      setAuthError('Please enter email and password');
      setApiMessage('');
      setIsApiLoading(false);
      return;
    }

    if (!isValidEmail(userEmail)) {
      setAuthError('Please enter a valid email address');
      setApiMessage('');
      setIsApiLoading(false);
      return;
    }

    try {
      console.log('🔐 Attempting login with:', {
        email: userEmail,
        passwordLength: userPassword.length,
        method: 'GET with query params'
      });

      // ENCODE the email properly (matching curl command)
      const encodedEmail = encodeURIComponent(userEmail);
      const encodedPassword = encodeURIComponent(userPassword);
      
      // Construct URL exactly like your curl command
      const loginUrl = `${API_BASE_URL}/api/login?email=${encodedEmail}&password=${encodedPassword}`;
      
      console.log('Login URL:', loginUrl);

      // Use fetch with GET method (matching curl)
      const response = await fetch(loginUrl, {
        method: 'GET',
        headers: {
          'Accept': 'application/json',
          'Content-Type': 'application/json',
        },
        credentials: 'include' // Include cookies if needed
      });

      console.log('Login response:', {
        status: response.status,
        statusText: response.statusText,
        ok: response.ok
      });

      // Parse response
      let responseData = {};
      try {
        const text = await response.text();
        responseData = text ? JSON.parse(text) : {};
        console.log('Response data:', responseData);
      } catch (parseError) {
        console.log('Response not JSON:', response.statusText);
      }

      if (response.ok) {
        // Check for success indicators
        const hasUserData = responseData.id || responseData.email || responseData.username;
        const hasSuccessMessage = responseData.message && 
          (responseData.message.toLowerCase().includes('success') || 
           responseData.message.toLowerCase().includes('login'));
        
        if (hasUserData || hasSuccessMessage || response.status === 200) {
          console.log('✅ Login successful');
          
          // Store user info
          const userInfo = {
            email: userEmail,
            username: responseData.username || userEmail.split('@')[0],
            loginTime: Date.now(),
            id: responseData.id || Date.now().toString(),
            token: responseData.token || responseData.sessionId || null
          };
          
          localStorage.setItem("resume_builder_user", JSON.stringify(userInfo));
          localStorage.setItem("user_email", userEmail);

          setIsAuthenticated(true);
          setUserEmail(userEmail);
          setApiMessage("✅ Login successful!");
          
          // Auto-check for existing resume
          setTimeout(() => {
            checkExistingResume(userEmail);
          }, 1000);

          setAuthData({
            username: '',
            email: '',
            password: '',
            confirmPassword: ''
          });
          
          testBackendConnection();
        } else {
          setAuthError('❌ Login response missing user data');
          setApiMessage('');
        }
      } else {
        // HTTP error
        const errorMsg = responseData.message || responseData.error || response.statusText;
        
        if (response.status === 401) {
          setAuthError('❌ Invalid email or password');
        } else if (response.status === 404) {
          setAuthError('❌ User not found. Please register first.');
        } else if (response.status === 400) {
          setAuthError('❌ Bad request. Please check your input.');
        } else {
          setAuthError(`❌ Login failed (${response.status}): ${errorMsg}`);
        }
        setApiMessage('');
      }

    } catch (error) {
      console.error("Login process error:", error);
      
      if (error.name === 'TypeError' && error.message.includes('Failed to fetch')) {
        setAuthError('❌ Cannot connect to server. Check if backend is running on port 8080.');
        setConnectionStatus('disconnected');
      } else {
        setAuthError(`❌ Network error: ${error.message}`);
      }
      
      setApiMessage('');
    } finally {
      setIsApiLoading(false);
    }
  };

  // Test if user exists in database
  const testUserExistence = async (email) => {
    try {
      // Try to login with dummy password to see if user exists
      const encodedEmail = encodeURIComponent(email);
      const response = await fetch(
        `${API_BASE_URL}/api/login?email=${encodedEmail}&password=dummy`,
        {
          method: 'GET',
          headers: { 'Accept': 'application/json' }
        }
      );
      
      // If we get a 401, user exists but password is wrong
      // If we get a 404, user doesn't exist
      // If we get 200, user exists and password was correct (shouldn't happen with dummy)
      console.log('User existence check:', {
        email,
        status: response.status,
        exists: response.status !== 404
      });
      
      return response.status !== 404;
    } catch (error) {
      console.log('User existence check failed:', error.message);
      return null;
    }
  };

  // UPDATED: Registration function using GET with query parameters
  const handleRegister = async (e) => {
    e.preventDefault();
    setAuthError('');
    setApiMessage('Creating account...');
    setIsApiLoading(true);

    if (!authData.email || !authData.password) {
      setAuthError('Email and password are required');
      setApiMessage('');
      setIsApiLoading(false);
      return;
    }

    if (!isValidEmail(authData.email)) {
      setAuthError('Please enter a valid email address');
      setApiMessage('');
      setIsApiLoading(false);
      return;
    }

    if (authData.password !== authData.confirmPassword) {
      setAuthError('Passwords do not match');
      setApiMessage('');
      setIsApiLoading(false);
      return;
    }

    if (authData.password.length < 6) {
      setAuthError('Password must be at least 6 characters');
      setApiMessage('');
      setIsApiLoading(false);
      return;
    }

    try {
      console.log('📝 Attempting registration:', {
        email: authData.email.trim(),
        passwordLength: authData.password.length,
        method: 'GET with query params'
      });

      // ENCODE parameters properly
      const encodedEmail = encodeURIComponent(authData.email.trim());
      const encodedPassword = encodeURIComponent(authData.password);
      
      // Construct URL with query parameters (matching login pattern)
      const registerUrl = `${API_BASE_URL}/api/login/register?email=${encodedEmail}&password=${encodedPassword}`;
      
      console.log('Register URL:', registerUrl);

      // Use fetch with GET method (matching login pattern)
      const response = await fetch(registerUrl, {
        method: 'GET',
        headers: {
          'Accept': 'application/json',
          'Content-Type': 'application/json',
        },
        credentials: 'include'
      });

      console.log('Register response:', {
        status: response.status,
        statusText: response.statusText,
        ok: response.ok
      });

      let responseData = {};
      try {
        const text = await response.text();
        responseData = text ? JSON.parse(text) : {};
      } catch (parseError) {
        console.log('Response not JSON:', response.statusText);
      }

      if (response.ok) {
        // Check for conflict
        if (responseData.message && 
            (responseData.message.toLowerCase().includes('already exists') || 
             responseData.message.toLowerCase().includes('already registered') ||
             responseData.message.toLowerCase().includes('conflict'))) {
          setAuthError('❌ User already exists. Please login instead.');
          setApiMessage('');
        } else {
          // Registration successful
          const userInfo = {
            email: authData.email,
            username: authData.username || authData.email.split('@')[0],
            registrationTime: Date.now(),
            id: responseData.id || Date.now().toString()
          };
          
          localStorage.setItem('resume_builder_user', JSON.stringify(userInfo));
          localStorage.setItem('user_email', authData.email);

          setIsAuthenticated(true);
          setUserEmail(authData.email);
          setApiMessage('✅ Registration successful! Welcome to Resume Builder!');
          
          // Auto-check for existing resume
          setTimeout(() => {
            checkExistingResume(authData.email);
          }, 1000);
          
          setAuthData({
            username: '',
            email: '',
            password: '',
            confirmPassword: ''
          });
          
          testBackendConnection();
        }
      } else {
        // Handle different error statuses
        if (response.status === 409) {
          setAuthError('❌ User already exists. Please login instead.');
        } else if (response.status === 400) {
          setAuthError('❌ Invalid registration data. Please check your input.');
        } else if (response.status === 500) {
          setAuthError('❌ Server error. Please try again later.');
        } else {
          const errorMsg = responseData.message || 
                          responseData.error || 
                          `Registration failed (${response.status})`;
          setAuthError(`❌ ${errorMsg}`);
        }
        setApiMessage('');
      }
    } catch (error) {
      console.error("Registration error:", error);
      
      if (error.name === 'TypeError' && error.message.includes('Failed to fetch')) {
        setAuthError('❌ Cannot connect to server. Check if backend is running on port 8080.');
        setConnectionStatus('disconnected');
      } else {
        setAuthError(`❌ Registration failed: ${error.message}`);
      }
      
      setApiMessage('');
    } finally {
      setIsApiLoading(false);
    }
  };

  const handleLogout = () => {
    localStorage.removeItem('resume_builder_user');
    localStorage.removeItem('user_email');
    setIsAuthenticated(false);
    setUserEmail('');
    setExistingResume(null);
    setFormData({
      fullName: '',
      email: '',
      phone: '',
      address: '',
      personalLinks: { GitHub: '', LinkedIn: '', Portfolio: '' },
      summary: '',
      experience: [{ 
        id: Date.now(),
        company: '', 
        position: '',
        type: '', 
        duration: '',
        points: [''] 
      }],
      education: [{ 
        id: Date.now(),
        institution: '', 
        degree: '', 
        score: '', 
        year: '',
        location: ''
      }],
      projects: [{ 
        id: Date.now(),
        name: '', 
        points: [''],
        technologies: ''
      }],
      technicalSkills: {
        languages: '',
        frontEnd: '',
        backEnd: '',
        database: '',
        tools: ''
      }
    });
    setApiMessage('👋 Logged out successfully');
    setTimeout(() => setApiMessage(''), 3000);
  };

  // Test exact curl command
 
  // Test login methods
  const testLoginMethods = async () => {
    const email = authData.email || 'test@example.com';
    const password = authData.password || 'test123';
    
    console.log('Testing login methods for:', email);
    
    // Test GET (matching curl)
    try {
      const encodedEmail = encodeURIComponent(email);
      const encodedPassword = encodeURIComponent(password);
      
      const getResponse = await fetch(
        `${API_BASE_URL}/api/login?email=${encodedEmail}&password=${encodedPassword}`,
        { 
          method: 'GET',
          headers: { 'Accept': 'application/json' }
        }
      );
      console.log('GET Response:', getResponse.status, getResponse.statusText);
      
      if (getResponse.ok) {
        const data = await getResponse.json();
        console.log('GET Success:', data);
        return { method: 'GET', success: true, data };
      }
    } catch (error) {
      console.log('GET Error:', error.message);
    }
    
    // Also test POST (just in case)
    try {
      const postResponse = await fetch(`${API_BASE_URL}/api/login`, {
        method: 'POST',
        headers: { 
          'Content-Type': 'application/json',
          'Accept': 'application/json' 
        },
        body: JSON.stringify({ email, password })
      });
      console.log('POST Response:', postResponse.status, postResponse.statusText);
      
      if (postResponse.ok) {
        const data = await postResponse.json();
        console.log('POST Success:', data);
        return { method: 'POST', success: true, data };
      }
    } catch (error) {
      console.log('POST Error:', error.message);
    }
    
    return { success: false };
  };

  const nextFormStep = () => {
    if (formStep < 5) {
      setFormStep(formStep + 1);
      window.scrollTo(0, 0);
    }
  };

  const prevFormStep = () => {
    if (formStep > 1) {
      setFormStep(formStep - 1);
      window.scrollTo(0, 0);
    }
  };

  // Add/Remove functions
  const addExperience = () => {
    setFormData({
      ...formData,
      experience: [...formData.experience, { 
        id: Date.now(),
        company: '', 
        position: '',
        type: '', 
        duration: '',
        points: [''] 
      }]
    });
  };

  const removeExperience = (index) => {
    if (formData.experience.length > 1) {
      const newExperience = formData.experience.filter((_, i) => i !== index);
      setFormData({ ...formData, experience: newExperience });
    }
  };

  const addExperiencePoint = (expIndex) => {
    const newExperience = [...formData.experience];
    newExperience[expIndex].points.push('');
    setFormData({ ...formData, experience: newExperience });
  };

  const removeExperiencePoint = (expIndex, pointIndex) => {
    const newExperience = [...formData.experience];
    if (newExperience[expIndex].points.length > 1) {
      newExperience[expIndex].points.splice(pointIndex, 1);
      setFormData({ ...formData, experience: newExperience });
    }
  };

  const addProject = () => {
    setFormData({
      ...formData,
      projects: [...formData.projects, { 
        id: Date.now(),
        name: '', 
        points: [''],
        technologies: ''
      }]
    });
  };

  const removeProject = (index) => {
    if (formData.projects.length > 1) {
      const newProjects = formData.projects.filter((_, i) => i !== index);
      setFormData({ ...formData, projects: newProjects });
    }
  };

  const addProjectPoint = (projIndex) => {
    const newProjects = [...formData.projects];
    newProjects[projIndex].points.push('');
    setFormData({ ...formData, projects: newProjects });
  };

  const removeProjectPoint = (projIndex, pointIndex) => {
    const newProjects = [...formData.projects];
    if (newProjects[projIndex].points.length > 1) {
      newProjects[projIndex].points.splice(pointIndex, 1);
      setFormData({ ...formData, projects: newProjects });
    }
  };

  // Enhanced Download PDF with Material Design
  const downloadPDF = async () => {
  setIsLoading(true);
  setExportProgress({ type: 'PDF', progress: 0 });
  
  try {
    const element = resumeRef.current;
    if (!element) throw new Error('Resume element not found');

    // 1. DYNAMIC NAME HANDLING
    const rawName = formData.fullName?.trim() || 'Resume';
    const safeFileName = `${rawName.replace(/\s+/g, '_')}_Resume.pdf`;

    // 2. APPLY TEMPORARY STYLES FOR CLEAN FORMATTING
    const originalStyles = {
      width: element.style.width,
      padding: element.style.padding,
      background: element.style.background,
      fontSize: element.style.fontSize,
      lineHeight: element.style.lineHeight,
      fontFamily: element.style.fontFamily,
      color: element.style.color
    };

    // Store all computed styles to restore later
    const computedStyles = window.getComputedStyle(element);
    const originalClasses = element.className;
    
    // Apply PDF-friendly styles
    element.style.width = '210mm';
    element.style.minWidth = '210mm';
    element.style.maxWidth = '210mm';
    element.style.padding = '15mm 20mm';
    element.style.margin = '0';
    element.style.background = '#ffffff';
    element.style.fontSize = '11pt';
    element.style.lineHeight = '1.3';
    element.style.fontFamily = "'Segoe UI', 'Calibri', 'Arial', sans-serif";
    element.style.color = '#000000';
    element.style.boxSizing = 'border-box';

    // 3. CREATE AND APPEND TEMPORARY STYLES (WITH DATA ATTRIBUTE)
    const style = document.createElement('style');
    style.setAttribute('data-pdf-temp', 'true');
    style.innerHTML = `
      /* PDF-specific styles */
      body { 
        margin: 0 !important; 
        padding: 0 !important;
        -webkit-print-color-adjust: exact !important;
        print-color-adjust: exact !important;
      }
      
      * {
        box-sizing: border-box;
        -webkit-box-sizing: border-box;
        -moz-box-sizing: border-box;
      }
      
      /* Resume container styling */
      .resume-container {
        width: 210mm !important;
        min-height: 297mm !important;
        background: white !important;
        font-family: 'Segoe UI', 'Calibri', 'Arial', sans-serif !important;
        font-size: 11pt !important;
        line-height: 1.3 !important;
        color: #000000 !important;
        margin: 0 auto !important;
        padding: 15mm 20mm !important;
      }
      
      /* Header styling */
      .resume-header h1 {
        font-size: 24pt !important;
        font-weight: bold !important;
        color: #2c3e50 !important;
        margin-bottom: 5mm !important;
        padding-bottom: 3mm !important;
        border-bottom: 2px solid #3498db !important;
      }
      
      /* Contact info */
      .contact-info {
        display: flex !important;
        flex-wrap: wrap !important;
        gap: 10px !important;
        margin-bottom: 15px !important;
        font-size: 10pt !important;
      }
      
      /* Section titles */
      .section-title {
        font-size: 14pt !important;
        font-weight: 600 !important;
        color: #2c3e50 !important;
        margin: 15px 0 10px 0 !important;
        padding-bottom: 5px !important;
        border-bottom: 1px solid #eee !important;
      }
      
      /* Experience items */
      .experience-item {
        margin-bottom: 12px !important;
        page-break-inside: avoid !important;
      }
      
      .job-header {
        display: flex !important;
        justify-content: space-between !important;
        margin-bottom: 5px !important;
      }
      
      .job-title {
        font-weight: bold !important;
        color: #2c3e50 !important;
      }
      
      .company {
        font-style: italic !important;
        color: #555 !important;
      }
      
      .date {
        color: #777 !important;
        font-size: 10pt !important;
      }
      
      /* Lists */
      ul, ol {
        margin: 8px 0 8px 20px !important;
        padding-left: 0 !important;
      }
      
      li {
        margin-bottom: 4px !important;
        line-height: 1.4 !important;
      }
      
      /* Skills */
      .skills-list {
        display: flex !important;
        flex-wrap: wrap !important;
        gap: 8px !important;
        margin: 10px 0 !important;
      }
      
      .skill-tag {
        background: #f0f8ff !important;
        border: 1px solid #d1e7ff !important;
        padding: 4px 10px !important;
        border-radius: 3px !important;
        font-size: 10pt !important;
      }
      
      /* Avoid page breaks */
      .avoid-break {
        page-break-inside: avoid !important;
      }
      
      /* Links */
      a {
        color: #0066cc !important;
        text-decoration: none !important;
      }
      
      /* Tables */
      table {
        border-collapse: collapse !important;
        width: 100% !important;
        margin: 10px 0 !important;
      }
      
      th, td {
        border: 1px solid #ddd !important;
        padding: 8px !important;
        text-align: left !important;
      }
      
      th {
        background: #f5f5f5 !important;
        font-weight: bold !important;
      }
    `;
    
    document.head.appendChild(style);
    setExportProgress({ type: 'PDF', progress: 30 });

    // 4. CREATE OPTIMIZED HTML FOR PDF
    const htmlContent = element.outerHTML;
    
    setExportProgress({ type: 'PDF', progress: 60 });

    // 5. GENERATE PDF USING html2pdf (BETTER THAN html2canvas)
    const opt = {
      margin: 0,
      filename: safeFileName,
      image: { type: 'jpeg', quality: 0.98 },
      html2canvas: { 
        scale: 2,
        useCORS: true,
        letterRendering: true,
        allowTaint: true,
        backgroundColor: '#ffffff',
        logging: false
      },
      jsPDF: { 
        unit: 'mm', 
        format: 'a4', 
        orientation: 'portrait',
        compress: true
      },
      pagebreak: { 
        mode: ['avoid-all', 'css', 'legacy'] 
      }
    };

    setExportProgress({ type: 'PDF', progress: 80 });

    // Use html2pdf instead of html2canvas directly
    await html2pdf().set(opt).from(element).save();
    
    setExportProgress({ type: 'PDF', progress: 100 });
    toast.success('PDF downloaded successfully!');

  } catch (error) {
    console.error('PDF generation error:', error);
    toast.error('Failed to generate PDF: ' + (error.message || 'Unknown error'));
  } finally {
    // 6. RESTORE ORIGINAL STYLES
    const element = resumeRef.current;
    if (element) {
      element.style.width = originalStyles.width;
      element.style.padding = originalStyles.padding;
      element.style.background = originalStyles.background;
      element.style.fontSize = originalStyles.fontSize;
      element.style.lineHeight = originalStyles.lineHeight;
      element.style.fontFamily = originalStyles.fontFamily;
      element.style.color = originalStyles.color;
      element.style.minWidth = '';
      element.style.maxWidth = '';
      element.style.margin = '';
      element.style.boxSizing = '';
    }
    
    // Remove temporary styles
    const tempStyle = document.querySelector('style[data-pdf-temp]');
    if (tempStyle) {
      tempStyle.remove();
    }
    
    setIsLoading(false);
    setTimeout(() => setExportProgress(null), 1000);
  }
};
  // Download as Word Document (DOCX) with Material Design
  // Alternative: Simple text-based DOCX download
// Download as Word (Simpler Approach)
// Fixed downloadWord function
const downloadWord = async () => {
  setLoading(true);
  try {
    const experienceList = formData.experience || [];
    const projectList = formData.projects || [];

    // --- ONE PAGE VALIDATION ---
    const totalPoints = experienceList.reduce((acc, exp) => 
      acc + (exp.points ? exp.points.filter(p => p.trim() !== "").length : 0), 0) + 
      projectList.reduce((acc, proj) => 
      acc + (proj.points ? proj.points.filter(p => p.trim() !== "").length : 0), 0);
    
    // If text is too long, show your frontend notification
    if (totalPoints > 22) {
      if (typeof showNotification === 'function') {
        showNotification("Content too long for one page. Please remove 1-2 bullet points.", "error");
      } else {
        alert("Content is too long for one page.");
      }
      setLoading(false);
      return; 
    }

    const formatUrl = (url) => {
      if (!url) return '';
      return url.startsWith('http') ? url : `https://${url}`;
    };

    const htmlContent = `
<!DOCTYPE html>
<html>
<head>
    <meta charset="UTF-8">
    <style>
        @page { margin: 0.5in; }
        body { 
            font-family: "Times New Roman", Times, serif; 
            line-height: 1.2; 
            color: #000; 
            font-size: 10.5pt; 
        }
        .header { text-align: center; margin-bottom: 8pt; }
        .name { font-size: 17pt; font-weight: bold; text-transform: uppercase; margin: 0; }
        h2 { 
            font-size: 11.5pt; 
            border-bottom: 1px solid #000; 
            text-transform: uppercase; 
            margin: 12pt 0 4pt 0; 
            font-weight: bold; 
        }
        .table-full { width: 100%; border-collapse: collapse; }
        /* REMOVING DOUBLE DOTS: Standard padding for clean bullets */
        ul { margin: 2pt 0; padding-left: 18pt; list-style-type: disc; }
        li { margin-bottom: 2pt; padding-left: 2pt; }
        a { color: #000; text-decoration: underline; }
    </style>
</head>
<body>
    <div class="header">
        <p class="name">${formData.fullName || 'MAHARUDRA YADAV'}</p>
        <p>${formData.address} | ${formData.phone} | ${formData.email}<br>
        ${formData.personalLinks?.LinkedIn ? `<a href="${formatUrl(formData.personalLinks.LinkedIn)}">LinkedIn</a>` : ''} 
        ${formData.personalLinks?.GitHub ? ` | <a href="${formatUrl(formData.personalLinks.GitHub)}">GitHub</a>` : ''}</p>
    </div>

    <h2>Summary</h2>
    <p style="margin: 0;">${formData.summary}</p>

    <h2>Education</h2>
    ${(formData.education || []).map(edu => `
        <table class="table-full">
            <tr><td align="left"><strong>${edu.institution}</strong></td><td align="right"><strong>${edu.year}</strong></td></tr>
            <tr><td>${edu.degree} | CGPA: ${edu.score}</td><td align="right">${edu.location}</td></tr>
        </table>
    `).join('')}

    <h2>Projects</h2>
    ${projectList.map(proj => `
        <div style="margin-bottom: 6pt;">
            <strong>${proj.name}</strong> | <em>${proj.technologies}</em>
            <ul>
                ${(proj.points || [])
                    .filter(p => p.trim() !== "" && p.trim() !== "•") // Removes accidental dots
                    .map(p => `<li>${p.replace(/^[•\-\*]\s*/, '')}</li>`) // Strips existing dots from text
                    .join('')}
            </ul>
        </div>
    `).join('')}

    ${experienceList.some(e => e.company) ? `
    <h2>Experience</h2>
    ${experienceList.filter(e => e.company).map(exp => `
        <table class="table-full" style="margin-top:4pt;">
            <tr><td align="left"><strong>${exp.company}</strong></td><td align="right"><strong>${exp.duration}</strong></td></tr>
            <tr><td><em>${exp.position}</em></td><td align="right"><em>${exp.location}</em></td></tr>
        </table>
        <ul>
            ${(exp.points || [])
                .filter(p => p.trim() !== "" && p.trim() !== "•")
                .map(p => `<li>${p.replace(/^[•\-\*]\s*/, '')}</li>`) 
                .join('')}
        </ul>
    `).join('')}` : ''}

    <h2>Technical Skills</h2>
    <p style="margin: 2pt 0;"><strong>Languages:</strong> ${formData.technicalSkills.languages}</p>
    <p style="margin: 2pt 0;"><strong>Technologies:</strong> ${formData.technicalSkills.backEnd}</p>
    <p style="margin: 2pt 0;"><strong>Tools:</strong> ${formData.technicalSkills.tools}</p>
</body>
</html>`;

    const blob = new Blob([htmlContent], { type: 'application/msword' });
    
    // FILE NAME FIX: Safe naming with underscores
    const safeName = (formData.fullName || "Resume").trim().replace(/\s+/g, '_');
    saveAs(blob, `${safeName}_Resume.doc`);
    
  } catch (error) {
    console.error("Download Error:", error);
  } finally {
    setLoading(false);
  }
};// Add this function if it's missing
const showNotification = (message, type = 'success') => {
  if (setNotification) {
    setNotification({ message, type });
    setTimeout(() => {
      if (setNotification) {
        setNotification({ message: '', type: '' });
      }
    }, 3000);
  } else {
    console.log(`Notification (${type}): ${message}`);
  }
};
  // Download as PNG Image with Material Design
  const downloadPNG = async () => {
    setIsLoading(true);
    setExportProgress({ type: 'PNG', progress: 0 });
    setApiMessage('Generating PNG image...');
    
    try {
      const element = resumeRef.current;
      if (!element) throw new Error('Resume element not found');
      
      setExportProgress({ type: 'PNG', progress: 30 });
      
      const originalBackground = element.style.background;
      element.style.background = '#ffffff';
      
      // Apply Material Design styles for PNG
      const tempElement = element.cloneNode(true);
      const sections = tempElement.querySelectorAll('.section-title-full');
      sections.forEach(section => {
        section.style.color = '#1976d2';
        section.style.borderBottom = '2px solid #1976d2';
      });
      
      const dataUrl = await html2canvas(tempElement, {
        quality: 1.0,
        scale: 2,
        backgroundColor: '#ffffff',
        useCORS: true,
        logging: false
      });
      
      setExportProgress({ type: 'PNG', progress: 70 });
      
      element.style.background = originalBackground;
      
      const link = document.createElement('a');
      link.download = `${formData.fullName.replace(/[^a-zA-Z0-9]/g, '_') || 'resume'}.png`;
      link.href = dataUrl.toDataURL('image/png');
      link.click();
      
      setExportProgress({ type: 'PNG', progress: 100 });
      setApiMessage('✅ PNG image downloaded successfully!');
      
      setTimeout(() => {
        setExportProgress({ type: '', progress: 0 });
        setApiMessage('');
      }, 3000);
      
    } catch (error) {
      console.error('PNG generation error:', error);
      setApiError(`❌ PNG generation failed: ${error.message}`);
      setTimeout(() => {
        setApiError('');
        setExportProgress({ type: '', progress: 0 });
      }, 5000);
    } finally {
      setIsLoading(false);
    }
  };

const formatSocialLink = (link) => {
  // Example: Remove 'https://' or format as needed
  if (!link) return '';
  
  // Example 1: Just return the link as is
  return link;
  
  // Example 2: Remove protocol
  // return link.replace(/^https?:\/\//, '');
  
  // Example 3: Extract username
  // const match = link.match(/(?:https?:\/\/)?(?:www\.)?([^\/]+)/);
  // return match ? match[1] : link;
};
  // Download as Text File
  const downloadText = async () => {
    setIsLoading(true);
    setApiMessage('Generating text file...');
    
    try {
      const textContent = `
${'='.repeat(60)}
PROFESSIONAL RESUME
${'='.repeat(60)}

Name: ${formData.fullName || 'Not specified'}
Email: ${formData.email || 'Not specified'}
Phone: ${formData.phone || 'Not specified'}
Location: ${formData.address || 'Not specified'}

${formData.personalLinks.GitHub ? `GitHub: ${formatSocialLink('github', formData.personalLinks.GitHub)}` : ''}
${formData.personalLinks.LinkedIn ? `LinkedIn: ${formatSocialLink('linkedin', formData.personalLinks.LinkedIn)}` : ''}
${formData.personalLinks.Portfolio ? `Portfolio: ${formatSocialLink('portfolio', formData.personalLinks.Portfolio)}` : ''}

${'-'.repeat(60)}
SUMMARY
${'-'.repeat(60)}
${formData.summary || 'Not specified'}

${'-'.repeat(60)}
EXPERIENCE
${'-'.repeat(60)}
${formData.experience.filter(exp => exp.company.trim()).map(exp => `
Company: ${exp.company}
Position: ${exp.position}
Type: ${exp.type}
Duration: ${exp.duration}
${exp.points.filter(p => p.trim()).map(p => `  • ${p}`).join('\n')}
`).join('\n')}

${'-'.repeat(60)}
EDUCATION
${'-'.repeat(60)}
${formData.education.filter(edu => edu.institution.trim()).map(edu => `
Institution: ${edu.institution}
Degree: ${edu.degree}
Score: ${edu.score}
Year: ${edu.year}
Location: ${edu.location}
`).join('\n')}

${'-'.repeat(60)}
PROJECTS
${'-'.repeat(60)}
${formData.projects.filter(proj => proj.name.trim()).map(proj => `
Project: ${proj.name}
Technologies: ${proj.technologies}
${proj.points.filter(p => p.trim()).map(p => `  • ${p}`).join('\n')}
`).join('\n')}

${'-'.repeat(60)}
TECHNICAL SKILLS
${'-'.repeat(60)}
${Object.entries(formData.technicalSkills)
  .filter(([_, value]) => value.trim())
  .map(([key, value]) => `${key}: ${value}`)
  .join('\n')}

${'='.repeat(60)}
Generated on: ${new Date().toLocaleDateString()}
${'='.repeat(60)}
      `.trim();
      
      const blob = new Blob([textContent], { type: 'text/plain;charset=utf-8' });
      const fileName = `${formData.fullName.replace(/[^a-zA-Z0-9]/g, '_') || 'resume'}.txt`;
      saveAs(blob, fileName);
      
      setApiMessage('✅ Text file downloaded successfully!');
      setTimeout(() => setApiMessage(''), 3000);
      
    } catch (error) {
      console.error('Text file generation error:', error);
      setApiError(`❌ Text file generation failed: ${error.message}`);
      setTimeout(() => setApiError(''), 5000);
    } finally {
      setIsLoading(false);
    }
  };

  // Form validation
  const validateForm = () => {
    const errors = [];
    
    if (!formData.fullName.trim()) {
      errors.push('Full name is required');
    }
    
    if (!formData.email.trim()) {
      errors.push('Email is required');
    } else if (!isValidEmail(formData.email)) {
      errors.push('Valid email is required');
    }
    
    if (!formData.summary.trim()) {
      errors.push('Professional summary is required');
    }
    
    return errors;
  };

  // Save Resume to Backend API
  const saveResumeToBackend = async () => {
    if (isApiLoading || isSaving) return;
    
    setIsSaving(true);
    setIsApiLoading(true);
    setApiMessage('');
    setApiError('');
    
    try {
      const user = JSON.parse(localStorage.getItem('resume_builder_user') || '{}');
      const requestEmail = user.email || formData.email || userEmail || localStorage.getItem('user_email');
      
      if (!requestEmail) {
        setApiError('❌ Please enter your email address');
        setIsSaving(false);
        setIsApiLoading(false);
        return;
      }
      
      const cleanEmail = requestEmail.trim();
      
      // Form validation
      const validationErrors = validateForm();
      if (validationErrors.length > 0) {
        setApiError(`❌ Please fix the following:\n${validationErrors.join('\n')}`);
        setIsSaving(false);
        setIsApiLoading(false);
        return;
      }
      
      if (!isValidEmail(cleanEmail)) {
        setApiError('❌ Please enter a valid email address');
        setIsSaving(false);
        setIsApiLoading(false);
        return;
      }
      
      // Use axios for saving resume (POST request)
      const requestData = {
        email: formData.email.trim() || cleanEmail,
        fullName: formData.fullName.trim() || '',
        phone: formData.phone.trim() || '',
        address: formData.address.trim() || '',
        personalLinks: {
          GitHub: formData.personalLinks.GitHub.trim() || '',
          LinkedIn: formData.personalLinks.LinkedIn.trim() || '',
          Portfolio: formData.personalLinks.Portfolio.trim() || ''
        },
        summary: formData.summary.trim() || ''
      };
      
      // Education
      const educationData = formData.education
        .filter(edu => edu.institution.trim())
        .map(edu => ({
          level: "Graduation",
          institution: edu.institution,
          degree: edu.degree || '',
          score: edu.score || '',
          year: edu.year || '',
          location: edu.location || ''
        }));
      
      if (educationData.length > 0) {
        requestData.education = educationData;
      }
      
      // Projects
      const projectsData = formData.projects
        .filter(project => project.name.trim())
        .map(project => ({
          name: project.name,
          description: project.points.filter(point => point.trim()).join(' • ') || '',
          technologies: project.technologies || ''
        }));
      
      if (projectsData.length > 0) {
        requestData.projects = projectsData;
      }
      
      // Technical Skills
      const techSkills = [];
      if (formData.technicalSkills.languages.trim()) techSkills.push(formData.technicalSkills.languages);
      if (formData.technicalSkills.frontEnd.trim()) techSkills.push(formData.technicalSkills.frontEnd);
      if (formData.technicalSkills.backEnd.trim()) techSkills.push(formData.technicalSkills.backEnd);
      if (formData.technicalSkills.database.trim()) techSkills.push(formData.technicalSkills.database);
      if (formData.technicalSkills.tools.trim()) techSkills.push(formData.technicalSkills.tools);
      
      if (techSkills.length > 0) {
        requestData.technicalSkills = techSkills.join(', ');
      }
      
      // Additional Info
      requestData.additionalInfo = {
        "Certifications": "Java Full Stack Development, Playwright Automation",
        "Languages": "English, Hindi, Marathi",
        "Soft Skills": "Teamwork, Flexibility, Communication",
        "Subject Proficiency": "Database, OS, Networking, OOPS"
      };

      console.log('💾 Saving resume data:', requestData);
      
      const response = await apiClient.post('/api/resumes/save', requestData);
      
      if (response.status === 200 || response.status === 201) {
        setApiMessage('✅ Resume saved successfully!');
        setExistingResume(requestData);
        
        // Auto-update local storage with latest email if changed
        if (formData.email.trim() && formData.email.trim() !== user.email) {
          const updatedUser = { ...user, email: formData.email.trim() };
          localStorage.setItem('resume_builder_user', JSON.stringify(updatedUser));
          localStorage.setItem('user_email', formData.email.trim());
        }
      }
      
    } catch (error) {
      console.error('Save Resume Error Details:', {
        message: error.message,
        response: error.response?.data,
        status: error.response?.status,
        url: error.config?.url
      });
      
      if (error.code === 'ECONNABORTED') {
        setApiError('❌ Request timeout. Please check your network connection.');
      } else if (error.response) {
        switch (error.response.status) {
          case 400:
            setApiError('❌ Bad request. Please check your input data.');
            break;
          case 401:
            setApiError('❌ Session expired. Please login again.');
            handleLogout();
            break;
          case 409:
            setApiError('❌ Resume with this email already exists.');
            break;
          case 500:
            setApiError('❌ Server error. Please try again later.');
            break;
          default:
            setApiError(`❌ Error ${error.response.status}: ${error.response.data?.message || 'Failed to save resume'}`);
        }
      } else if (error.request) {
        setApiError('❌ No response from server. Check if backend is running on port 8080.');
        setConnectionStatus('disconnected');
      } else {
        setApiError(`❌ Error: ${error.message}`);
      }
      
    } finally {
      setIsSaving(false);
      setIsApiLoading(false);
      
      setTimeout(() => {
        setApiMessage('');
        setApiError('');
      }, 5000);
    }
  };

  // Handle input changes
  const handleInputChange = (section, field, value, index = null) => {
    if (index !== null) {
      const newArray = [...formData[section]];
      newArray[index][field] = value;
      setFormData({ ...formData, [section]: newArray });
    } else if (section.includes('.')) {
      const [main, sub] = section.split('.');
      setFormData({
        ...formData,
        [main]: {
          ...formData[main],
          [sub]: value
        }
      });
    } else {
      setFormData({ ...formData, [section]: value });
    }
    
    // Auto-check for existing resume when email changes
    if (section === 'email' && field === '') {
      debouncedCheckResume(value);
    }
  };

  const handleArrayFieldUpdate = (section, index, field, value) => {
    const newArray = [...formData[section]];
    newArray[index][field] = value;
    setFormData({ ...formData, [section]: newArray });
  };

  const handleNestedArrayUpdate = (section, index, subField, subIndex, value) => {
    const newArray = [...formData[section]];
    newArray[index][subField][subIndex] = value;
    setFormData({ ...formData, [section]: newArray });
  };

  // Calculate completion percentage
  const calculateCompletion = () => {
    const fields = [
      formData.fullName,
      formData.email,
      formData.summary,
      formData.experience.some(exp => exp.company.trim()),
      formData.education.some(edu => edu.institution.trim()),
      formData.projects.some(proj => proj.name.trim()),
      Object.values(formData.technicalSkills).some(skill => skill.trim())
    ];
    
    const completed = fields.filter(Boolean).length;
    return Math.round((completed / fields.length) * 100);
  };

  // Toggle preview visibility
  const togglePreviewVisibility = () => {
    setIsPreviewVisible(!isPreviewVisible);
  };

  // Quick test for existing users
  const testExistingUsers = async () => {
    console.log('🔍 Testing for existing users in database...');
    
    const commonEmails = [
      'admin@admin.com',
      'test@test.com',
      'user@example.com',
      'demo@demo.com',
      'admin@gmail.com',
      'test@gmail.com',
      'mby212001@gmail.com' // Added your test email
    ];
    
    for (const email of commonEmails) {
      try {
        const encodedEmail = encodeURIComponent(email);
        const response = await fetch(
          `${API_BASE_URL}/api/login?email=${encodedEmail}&password=test123`,
          {
            method: 'GET',
            headers: { 'Accept': 'application/json' }
          }
        );
        
        console.log(`User ${email}:`, {
          status: response.status,
          exists: response.status !== 404
        });
      } catch (error) {
        console.log(`User ${email} test failed:`, error.message);
      }
    }
  };

  // Export Progress Bar Component
  const ExportProgressBar = () => {
    if (!exportProgress.type) return null;
    
    return (
      <div className="export-progress-bar">
        <div className="progress-label">
          Generating {exportProgress.type}... {exportProgress.progress}%
        </div>
        <div className="progress-track">
          <div 
            className="progress-fill" 
            style={{ width: `${exportProgress.progress}%` }}
          />
        </div>
      </div>
    );
  };

  // Render export buttons
  const renderExportButtons = () => (
    <div className="export-options">
      <button 
        className="btn-action-full material-btn primary"
        onClick={downloadPDF}
        disabled={isLoading || isApiLoading}
        title="Download as PDF"
      >
        <FaFilePdf /> PDF
      </button>
      
      <button 
        className="btn-action-full material-btn secondary"
        onClick={downloadWord}
        disabled={isLoading || isApiLoading}
        title="Download as Word Document"
      >
        <FaFileWord /> Word
      </button>
      
      <button 
        className="btn-action-full material-btn accent"
        onClick={downloadPNG}
        disabled={isLoading || isApiLoading}
        title="Download as PNG Image"
      >
        <FaFileImage /> PNG
      </button>
      
      <button 
        className="btn-action-full material-btn"
        onClick={downloadText}
        disabled={isLoading || isApiLoading}
        title="Download as Text File"
      >
        <FaFileAlt /> Text
      </button>
    </div>
  );

  // Login/Auth Screen
  if (!isAuthenticated) {
    return (
      <div className="auth-container">
        <div className="auth-wrapper">
          <div className="auth-card">
            <div className="auth-header">
              <h1><FaHome /> Resume Builder</h1>
              <p>Create professional resumes in minutes</p>
              <div className={`connection-status ${connectionStatus}`}>
                <FaNetworkWired /> 
                {connectionStatus === 'connected' && '✅ Backend Connected'}
                {connectionStatus === 'disconnected' && '❌ Backend Disconnected'}
                {connectionStatus === 'checking' && '⏳ Checking Connection...'}
              </div>
            </div>
            
            <div className="auth-tabs">
              <button 
                className={`auth-tab ${showLogin ? 'active' : ''}`}
                onClick={() => setShowLogin(true)}
                disabled={isApiLoading}
              >
                <FaUser /> Login
              </button>
              <button 
                className={`auth-tab ${!showLogin ? 'active' : ''}`}
                onClick={() => setShowLogin(false)}
                disabled={isApiLoading}
              >
                <FaUserPlus /> Register
              </button>
            </div>
            
            {showLogin ? (
              <form className="auth-form" onSubmit={handleLogin}>
                <h2>Welcome Back!</h2>
                <p className="auth-subtitle">Sign in to your account</p>
                
                <div className="form-group">
                  <label><FaEnvelope /> Email</label>
                  <div className="input-with-icon">
                    <FaUser className="input-icon" />
                    <input 
                      type="email" 
                      name="email"
                      placeholder="Enter your email"
                      value={authData.email}
                      onChange={handleAuthInput}
                      required
                      disabled={isApiLoading}
                      autoComplete="email"
                    />
                  </div>
                </div>
                
                <div className="form-group">
                  <label><FaKey /> Password</label>
                  <div className="input-with-icon">
                    <FaLock className="input-icon" />
                    <input 
                      type="password" 
                      name="password"
                      placeholder="Enter your password"
                      value={authData.password}
                      onChange={handleAuthInput}
                      required
                      disabled={isApiLoading}
                      autoComplete="current-password"
                    />
                  </div>
                </div>
                
                {authError && (
                  <div className="auth-error">
                    <FaExclamationTriangle /> {authError}
                  </div>
                )}
                
                <button 
                  type="submit" 
                  className="auth-submit material-btn primary"
                  disabled={isApiLoading}
                >
                  {isApiLoading ? (
                    <>
                      <FaSync className="spinner" /> Logging in...
                    </>
                  ) : (
                    <>
                      <FaUser /> Sign In
                    </>
                  )}
                </button>
                
                <div className="auth-footer">
                  <p>
                    Don't have an account? 
                    <button 
                      type="button" 
                      className="auth-switch"
                      onClick={() => setShowLogin(false)}
                      disabled={isApiLoading}
                    >
                      Sign up here
                    </button>
                  </p>
                </div>
              </form>
            ) : (
              <form className="auth-form" onSubmit={handleRegister}>
                <h2>Create Account</h2>
                <p className="auth-subtitle">Start building your resume today</p>
                
                <div className="form-group">
                  <label>Username (Optional)</label>
                  <div className="input-with-icon">
                    <FaUser className="input-icon" />
                    <input 
                      type="text" 
                      name="username"
                      placeholder="Choose a username"
                      value={authData.username}
                      onChange={handleAuthInput}
                      disabled={isApiLoading}
                      autoComplete="username"
                    />
                  </div>
                </div>
                
                <div className="form-group">
                  <label><FaEnvelope /> Email *</label>
                  <div className="input-with-icon">
                    <FaUser className="input-icon" />
                    <input 
                      type="email" 
                      name="email"
                      placeholder="Enter your email"
                      value={authData.email}
                      onChange={handleAuthInput}
                      required
                      disabled={isApiLoading}
                      autoComplete="email"
                    />
                  </div>
                </div>
                
                <div className="form-group">
                  <label><FaKey /> Password *</label>
                  <div className="input-with-icon">
                    <FaLock className="input-icon" />
                    <input 
                      type="password" 
                      name="password"
                      placeholder="Create a password (min. 6 characters)"
                      value={authData.password}
                      onChange={handleAuthInput}
                      required
                      minLength={6}
                      disabled={isApiLoading}
                      autoComplete="new-password"
                    />
                  </div>
                </div>
                
                <div className="form-group">
                  <label><FaKey /> Confirm Password *</label>
                  <div className="input-with-icon">
                    <FaLock className="input-icon" />
                    <input 
                      type="password" 
                      name="confirmPassword"
                      placeholder="Confirm your password"
                      value={authData.confirmPassword}
                      onChange={handleAuthInput}
                      required
                      minLength={6}
                      disabled={isApiLoading}
                      autoComplete="new-password"
                    />
                  </div>
                </div>
                
                {authError && (
                  <div className="auth-error">
                    <FaExclamationTriangle /> {authError}
                  </div>
                )}
                
                <button 
                  type="submit" 
                  className="auth-submit material-btn primary"
                  disabled={isApiLoading}
                >
                  {isApiLoading ? (
                    <>
                      <FaSync className="spinner" /> Creating Account...
                    </>
                  ) : (
                    <>
                      <FaUserPlus /> Create Account
                    </>
                  )}
                </button>
                
                <div className="auth-footer">
                  <p>
                    Already have an account? 
                    <button 
                      type="button" 
                      className="auth-switch"
                      onClick={() => setShowLogin(true)}
                      disabled={isApiLoading}
                    >
                      Sign in here
                    </button>
                  </p>
                </div>
              </form>
            )}
          </div>
        </div>
        
        {apiMessage && (
          <div className="api-status success">
            {apiMessage}
          </div>
        )}
      </div>
    );
  }

  // Main Application (Authenticated)
  return (
    <div className="app-container">
      <ExportProgressBar />
      
      {/* Top Navigation */}
      <nav className="top-nav">
        <button 
          className="mobile-menu-btn material-btn icon"
          onClick={() => setIsMobileMenuOpen(!isMobileMenuOpen)}
        >
          {isMobileMenuOpen ? <FaTimes /> : <FaBars />}
        </button>
        
        <div className="nav-left">
          <h1 className="nav-logo">
            <FaHome /> Resume Builder
          </h1>
          <span className="nav-user">
            <FaUser /> {userEmail.split('@')[0]}
          </span>
        </div>
        
        <div className={`nav-center ${isMobileMenuOpen ? 'mobile-open' : ''}`}>
          <div className="step-progress">
            {[1, 2, 3, 4, 5].map((step) => (
              <button
                key={step}
                className={`step-dot ${formStep === step ? 'active' : ''} ${formStep > step ? 'completed' : ''}`}
                onClick={() => {
                  setFormStep(step);
                  setIsMobileMenuOpen(false);
                }}
                title={`Step ${step}`}
              >
                {formStep > step ? <FaCheck /> : step}
              </button>
            ))}
          </div>
        </div>
        
        <div className={`nav-right ${isMobileMenuOpen ? 'mobile-open' : ''}`}>
          <button 
            className="btn-load-resume material-btn"
            onClick={() => checkExistingResume(userEmail || formData.email)}
            disabled={isCheckingResume || isApiLoading}
            title="Check for existing resume"
          >
            {isCheckingResume ? <FaSync className="spinner" /> : <FaSearch />}
            {isCheckingResume ? 'Checking...' : 'Check Resume'}
          </button>
          
          {existingResume && (
            <button 
              className="btn-load-resume material-btn success"
              onClick={loadExistingResume}
              disabled={isApiLoading}
              title="Load existing resume"
            >
              <FaDownload /> Load
            </button>
          )}
          
          <div className="completion-badge material-elevation-2">
            <span className="completion-percent">{calculateCompletion()}%</span>
          </div>
          
          <button 
            className="btn-action-icon material-btn icon"
            onClick={togglePreviewVisibility}
            title={isPreviewVisible ? "Hide Preview" : "Show Preview"}
            disabled={isApiLoading}
          >
            {isPreviewVisible ? <FaEyeSlash /> : <FaEye />}
          </button>
          
          <button className="logout-btn material-btn" onClick={handleLogout} title="Logout">
            <FaSignOutAlt /> <span className="logout-text">Logout</span>
          </button>
        </div>
      </nav>

      {/* Connection Status */}
      <div className={`connection-status-bar ${connectionStatus}`}>
        <FaNetworkWired />
        <span>
          {connectionStatus === 'connected' && '✅ Backend Connected'}
          {connectionStatus === 'disconnected' && '❌ Backend Disconnected - Check if server is running on port 8080'}
          {connectionStatus === 'checking' && '⏳ Checking Backend Connection...'}
        </span>
      </div>

      {/* API Status Message */}
      {(apiMessage || apiError) && (
        <div className={`api-status ${apiMessage ? 'success' : 'error'}`}>
          <div className="api-status-content">
            {apiMessage ? <FaCheck /> : <FaExclamationTriangle />}
            <span>{apiMessage || apiError}</span>
          </div>
        </div>
      )}

      {/* Main Content */}
      <main className="main-content-single">
        <div className={`full-screen-container ${isPreviewVisible ? '' : 'preview-hidden'}`}>
          {/* Left Panel: Form */}
          <div className="form-panel-full">
            <div className="form-header-full material-elevation-2">
              <h2>
                <span className="step-number material-elevation-1">{formStep}</span>
                <span className="step-title">
                  {formStep === 1 && "Basic Information"}
                  {formStep === 2 && "Professional Summary"}
                  {formStep === 3 && "Work Experience"}
                  {formStep === 4 && "Projects"}
                  {formStep === 5 && "Skills & Education"}
                </span>
              </h2>
              <button 
                className="btn-clear-form material-btn"
                onClick={clearFormData}
                disabled={isApiLoading}
                title="Clear all form data"
              >
                <FaTrash /> Clear
              </button>
            </div>

            <div className="form-content-full">
              {formStep === 1 && (
                <div className="form-step-full active">
                  <div className="form-group-full">
                    <label>Full Name *</label>
                    <input 
                      type="text" 
                      placeholder="John Doe"
                      value={formData.fullName}
                      onChange={e => handleInputChange('fullName', '', e.target.value)}
                      disabled={isApiLoading}
                      className="material-input"
                    />
                    {!formData.fullName.trim() && (
                      <div className="form-hint">
                        <FaInfoCircle /> Required field
                      </div>
                    )}
                  </div>
                  
                  <div className="form-row-full">
                    <div className="form-group-full">
                      <label>Email *</label>
                      <input 
                        type="email" 
                        placeholder="john@example.com"
                        value={formData.email}
                        onChange={e => handleInputChange('email', '', e.target.value)}
                        disabled={isApiLoading}
                        className="material-input"
                      />
                      {!isValidEmail(formData.email) && formData.email && (
                        <div className="form-error">
                          <FaExclamationTriangle /> Please enter a valid email
                        </div>
                      )}
                    </div>
                    <div className="form-group-full">
                      <label>Phone</label>
                      <input 
                        type="tel" 
                        placeholder="+1 (123) 456-7890"
                        value={formData.phone}
                        onChange={e => handleInputChange('phone', '', e.target.value)}
                        disabled={isApiLoading}
                        className="material-input"
                      />
                    </div>
                  </div>
                  
                  <div className="form-group-full">
                    <label>Location</label>
                    <input 
                      type="text" 
                      placeholder="City, State, Country"
                      value={formData.address}
                      onChange={e => handleInputChange('address', '', e.target.value)}
                      disabled={isApiLoading}
                      className="material-input"
                    />
                  </div>
                  
                  <div className="social-section-full">
                    <label>Social Links</label>
                    <div className="social-inputs-full">
                      <div className="social-input-full material-input">
                        <FaGithub />
                        <input 
                          type="text" 
                          placeholder="GitHub username or URL"
                          value={formData.personalLinks.GitHub}
                          onChange={e => handleInputChange('personalLinks.GitHub', '', e.target.value)}
                          disabled={isApiLoading}
                        />
                      </div>
                      <div className="social-input-full material-input">
                        <FaLinkedin />
                        <input 
                          type="text" 
                          placeholder="LinkedIn username or URL"
                          value={formData.personalLinks.LinkedIn}
                          onChange={e => handleInputChange('personalLinks.LinkedIn', '', e.target.value)}
                          disabled={isApiLoading}
                        />
                      </div>
                      <div className="social-input-full material-input">
                        <FaGlobe />
                        <input 
                          type="text" 
                          placeholder="Portfolio website URL"
                          value={formData.personalLinks.Portfolio}
                          onChange={e => handleInputChange('personalLinks.Portfolio', '', e.target.value)}
                          disabled={isApiLoading}
                        />
                      </div>
                    </div>
                  </div>
                </div>
              )}

              {formStep === 2 && (
                <div className="form-step-full active">
                  <div className="form-group-full">
                    <label>Professional Summary *</label>
                    <textarea 
                      placeholder="Experienced software developer with expertise in Java, Spring Boot, and API development..."
                      value={formData.summary}
                      onChange={e => handleInputChange('summary', '', e.target.value)}
                      rows={4}
                      disabled={isApiLoading}
                      maxLength={500}
                      className="material-input"
                    />
                    {!formData.summary.trim() && (
                      <div className="form-hint">
                        <FaInfoCircle /> Required field
                      </div>
                    )}
                    <div className="char-count">
                      {formData.summary.length}/500 characters
                    </div>
                  </div>
                </div>
              )}

              {formStep === 3 && (
                <div className="form-step-full active">
                  <div className="section-header-full">
                    <h3>Work Experience</h3>
                    <div className="section-actions">
                      <button 
                        type="button" 
                        className="btn-add-small material-btn primary" 
                        onClick={addExperience}
                        disabled={isApiLoading}
                      >
                        <FaPlus /> Add
                      </button>
                    </div>
                  </div>
                  
                  {formData.experience.map((exp, expIndex) => (
                    <div key={exp.id} className="form-card-full material-elevation-1">
                      <div className="card-header-full">
                        <h4>Experience {expIndex + 1}</h4>
                        <div className="card-actions">
                          {formData.experience.length > 1 && (
                            <button 
                              type="button" 
                              className="btn-remove-small material-btn icon"
                              onClick={() => removeExperience(expIndex)}
                              disabled={isApiLoading}
                            >
                              <FaMinus />
                            </button>
                          )}
                        </div>
                      </div>
                      
                      <div className="form-row-full">
                        <div className="form-group-full">
                          <label>Company</label>
                          <input 
                            type="text" 
                            placeholder="Google Inc."
                            value={exp.company}
                            onChange={e => handleArrayFieldUpdate('experience', expIndex, 'company', e.target.value)}
                            disabled={isApiLoading}
                            className="material-input"
                          />
                        </div>
                        <div className="form-group-full">
                          <label>Position</label>
                          <input 
                            type="text" 
                            placeholder="Software Engineer"
                            value={exp.position}
                            onChange={e => handleArrayFieldUpdate('experience', expIndex, 'position', e.target.value)}
                            disabled={isApiLoading}
                            className="material-input"
                          />
                        </div>
                      </div>
                      
                      <div className="form-row-full">
                        <div className="form-group-full">
                          <label>Type</label>
                          <select 
                            value={exp.type}
                            onChange={e => handleArrayFieldUpdate('experience', expIndex, 'type', e.target.value)}
                            disabled={isApiLoading}
                            className="material-input"
                          >
                            <option value="">Select Type</option>
                            <option value="Full-time">Full-time</option>
                            <option value="Part-time">Part-time</option>
                            <option value="Internship">Internship</option>
                            <option value="Contract">Contract</option>
                            <option value="Freelance">Freelance</option>
                          </select>
                        </div>
                        <div className="form-group-full">
                          <label>Duration</label>
                          <input 
                            type="text" 
                            placeholder="Jan 2022 - Present"
                            value={exp.duration}
                            onChange={e => handleArrayFieldUpdate('experience', expIndex, 'duration', e.target.value)}
                            disabled={isApiLoading}
                            className="material-input"
                          />
                        </div>
                      </div>
                      
                      <div className="form-group-full">
                        <label>Responsibilities</label>
                        {exp.points.map((point, pointIndex) => (
                          <div key={pointIndex} className="point-row-full">
                            <input 
                              type="text" 
                              placeholder="• Developed scalable applications..."
                              value={point}
                              onChange={e => handleNestedArrayUpdate('experience', expIndex, 'points', pointIndex, e.target.value)}
                              disabled={isApiLoading}
                              className="material-input"
                            />
                            {exp.points.length > 1 && (
                              <button 
                                type="button" 
                                className="btn-remove-point material-btn icon small"
                                onClick={() => removeExperiencePoint(expIndex, pointIndex)}
                                disabled={isApiLoading}
                              >
                                ×
                              </button>
                            )}
                          </div>
                        ))}
                        <button 
                          type="button" 
                          className="btn-add-point material-btn"
                          onClick={() => addExperiencePoint(expIndex)}
                          disabled={isApiLoading}
                        >
                          + Add Responsibility
                        </button>
                      </div>
                    </div>
                  ))}
                </div>
              )}

              {formStep === 4 && (
                <div className="form-step-full active">
                  <div className="section-header-full">
                    <h3>Projects</h3>
                    <div className="section-actions">
                      <button 
                        type="button" 
                        className="btn-add-small material-btn primary" 
                        onClick={addProject}
                        disabled={isApiLoading}
                      >
                        <FaPlus /> Add
                      </button>
                    </div>
                  </div>
                  
                  {formData.projects.map((project, projIndex) => (
                    <div key={project.id} className="form-card-full material-elevation-1">
                      <div className="card-header-full">
                        <h4>Project {projIndex + 1}</h4>
                        <div className="card-actions">
                          {formData.projects.length > 1 && (
                            <button 
                              type="button" 
                              className="btn-remove-small material-btn icon"
                              onClick={() => removeProject(projIndex)}
                              disabled={isApiLoading}
                            >
                              <FaMinus />
                            </button>
                          )}
                        </div>
                      </div>
                      
                      <div className="form-group-full">
                        <label>Project Name</label>
                        <input 
                          type="text" 
                          placeholder="E-Commerce Platform"
                          value={project.name}
                          onChange={e => handleArrayFieldUpdate('projects', projIndex, 'name', e.target.value)}
                          disabled={isApiLoading}
                          className="material-input"
                        />
                      </div>
                      
                      <div className="form-group-full">
                        <label>Key Features / Description</label>
                        {project.points.map((point, pointIndex) => (
                          <div key={pointIndex} className="point-row-full">
                            <input 
                              type="text" 
                              placeholder="• Built RESTful APIs..."
                              value={point}
                              onChange={e => handleNestedArrayUpdate('projects', projIndex, 'points', pointIndex, e.target.value)}
                              disabled={isApiLoading}
                              className="material-input"
                            />
                            {project.points.length > 1 && (
                              <button 
                                type="button" 
                                className="btn-remove-point material-btn icon small"
                                onClick={() => removeProjectPoint(projIndex, pointIndex)}
                                disabled={isApiLoading}
                              >
                                ×
                              </button>
                            )}
                          </div>
                        ))}
                        <button 
                          type="button" 
                          className="btn-add-point material-btn"
                          onClick={() => addProjectPoint(projIndex)}
                          disabled={isApiLoading}
                        >
                          + Add Feature
                        </button>
                      </div>
                      
                      <div className="form-group-full">
                        <label>Technologies Used</label>
                        <input 
                          type="text" 
                          placeholder="Java, Spring Boot, React, MySQL"
                          value={project.technologies}
                          onChange={e => handleArrayFieldUpdate('projects', projIndex, 'technologies', e.target.value)}
                          disabled={isApiLoading}
                          className="material-input"
                        />
                      </div>
                    </div>
                  ))}
                </div>
              )}

              {formStep === 5 && (
                <div className="form-step-full active">
                  <div className="section-header-full">
                    <h3>Technical Skills</h3>
                  </div>
                  
                  <div className="form-card-full material-elevation-1">
                    <div className="form-row-full">
                      <div className="form-group-full">
                        <label>Programming Languages</label>
                        <input 
                          type="text" 
                          placeholder="Java, Python, JavaScript, C++"
                          value={formData.technicalSkills.languages}
                          onChange={e => handleInputChange('technicalSkills.languages', '', e.target.value)}
                          disabled={isApiLoading}
                          className="material-input"
                        />
                      </div>
                      <div className="form-group-full">
                        <label>Frontend Technologies</label>
                        <input 
                          type="text" 
                          placeholder="React, HTML5, CSS3, Bootstrap"
                          value={formData.technicalSkills.frontEnd}
                          onChange={e => handleInputChange('technicalSkills.frontEnd', '', e.target.value)}
                          disabled={isApiLoading}
                          className="material-input"
                        />
                      </div>
                    </div>
                    
                    <div className="form-row-full">
                      <div className="form-group-full">
                        <label>Backend Technologies</label>
                        <input 
                          type="text" 
                          placeholder="Spring Boot, Node.js, Express.js"
                          value={formData.technicalSkills.backEnd}
                          onChange={e => handleInputChange('technicalSkills.backEnd', '', e.target.value)}
                          disabled={isApiLoading}
                          className="material-input"
                        />
                      </div>
                      <div className="form-group-full">
                        <label>Databases</label>
                        <input 
                          type="text" 
                          placeholder="MySQL, MongoDB, PostgreSQL"
                          value={formData.technicalSkills.database}
                          onChange={e => handleInputChange('technicalSkills.database', '', e.target.value)}
                          disabled={isApiLoading}
                          className="material-input"
                        />
                      </div>
                    </div>
                    
                    <div className="form-group-full">
                      <label>Tools & Platforms</label>
                      <input 
                        type="text" 
                        placeholder="Git, Docker, AWS, Jenkins, Kubernetes"
                        value={formData.technicalSkills.tools}
                        onChange={e => handleInputChange('technicalSkills.tools', '', e.target.value)}
                        disabled={isApiLoading}
                        className="material-input"
                      />
                    </div>
                  </div>
                  
                  <div className="section-header-full">
                    <h3>Education</h3>
                    <div className="section-actions">
                      <button 
                        type="button" 
                        className="btn-add-small material-btn primary"
                        onClick={() => {
                          setFormData({
                            ...formData,
                            education: [...formData.education, { 
                              id: Date.now(),
                              institution: '', 
                              degree: '', 
                              score: '', 
                              year: '',
                              location: ''
                            }]
                          });
                        }}
                        disabled={isApiLoading}
                      >
                        <FaPlus /> Add
                      </button>
                    </div>
                  </div>
                  
                  <div className="form-card-full material-elevation-1">
                    {formData.education.map((edu, index) => (
                      <div key={edu.id} className="education-form-full">
                        <div className="education-form-header">
                          <h4>Education {index + 1}</h4>
                          {formData.education.length > 1 && (
                            <button 
                              type="button" 
                              className="btn-remove-small material-btn icon"
                              onClick={() => {
                                const newEducation = formData.education.filter((_, i) => i !== index);
                                setFormData({ ...formData, education: newEducation });
                              }}
                              disabled={isApiLoading}
                            >
                              <FaMinus />
                            </button>
                          )}
                        </div>
                        
                        <div className="form-row-full">
                          <div className="form-group-full">
                            <label>Institution *</label>
                            <input 
                              type="text" 
                              placeholder="University Name"
                              value={edu.institution}
                              onChange={e => handleArrayFieldUpdate('education', index, 'institution', e.target.value)}
                              disabled={isApiLoading}
                              className="material-input"
                            />
                          </div>
                          <div className="form-group-full">
                            <label>Degree *</label>
                            <input 
                              type="text" 
                              placeholder="B.Tech Computer Science"
                              value={edu.degree}
                              onChange={e => handleArrayFieldUpdate('education', index, 'degree', e.target.value)}
                              disabled={isApiLoading}
                              className="material-input"
                            />
                          </div>
                        </div>
                        
                        <div className="form-row-full">
                          <div className="form-group-full">
                            <label>Score/GPA</label>
                            <input 
                              type="text" 
                              placeholder="8.5/10 or 3.7/4.0"
                              value={edu.score}
                              onChange={e => handleArrayFieldUpdate('education', index, 'score', e.target.value)}
                              disabled={isApiLoading}
                              className="material-input"
                            />
                          </div>
                          <div className="form-group-full">
                            <label>Year</label>
                            <input 
                              type="text" 
                              placeholder="2020-2024"
                              value={edu.year}
                              onChange={e => handleArrayFieldUpdate('education', index, 'year', e.target.value)}
                              disabled={isApiLoading}
                              className="material-input"
                            />
                          </div>
                        </div>
                        
                        <div className="form-group-full">
                          <label>Location</label>
                          <input 
                            type="text" 
                            placeholder="City, Country"
                            value={edu.location}
                            onChange={e => handleArrayFieldUpdate('education', index, 'location', e.target.value)}
                            disabled={isApiLoading}
                            className="material-input"
                          />
                        </div>
                      </div>
                    ))}
                  </div>
                </div>
              )}
            </div>

            {/* Form Navigation */}
            <div className="form-navigation-full">
              <button 
                className="btn-nav-full prev material-btn"
                onClick={prevFormStep}
                disabled={formStep === 1 || isApiLoading}
              >
                <FaChevronLeft /> Previous
              </button>
              
              <div className="step-indicator-full">
                Step {formStep} of 5
                <div className="completion-small">{calculateCompletion()}% Complete</div>
              </div>
              
              <button 
                className="btn-nav-full next material-btn primary"
                onClick={nextFormStep}
                disabled={isApiLoading}
              >
                {formStep === 5 ? 'Complete' : 'Next'} <FaChevronRight />
              </button>
            </div>
          </div>

          {/* Right Panel: Live Preview */}
          {isPreviewVisible && (
            <div className="preview-panel-full">
              <div className="preview-header-full material-elevation-2">
                <h3>Live Preview</h3>
                <div className="preview-actions-full">
                  <button 
                    className="btn-action-full material-btn"
                    onClick={() => checkExistingResume(userEmail || formData.email)}
                    disabled={isCheckingResume || isApiLoading}
                    title="Check for existing resume"
                  >
                    {isCheckingResume ? <FaSync className="spinner" /> : <FaSearch />}
                    {isCheckingResume ? 'Checking...' : 'Check'}
                  </button>
                  
                  {existingResume && (
                    <button 
                      className="btn-action-full material-btn success"
                      onClick={loadExistingResume}
                      disabled={isApiLoading}
                      title="Load existing resume"
                    >
                      <FaDownload /> Load
                    </button>
                  )}
                  
                  <button 
                    className="btn-action-full material-btn primary"
                    onClick={saveResumeToBackend}
                    disabled={isSaving || isApiLoading}
                    title="Save resume to database"
                  >
                    {isSaving ? <FaSync className="spinner" /> : <FaSave />}
                    {isSaving ? 'Saving...' : 'Save'}
                  </button>
                  
                  {renderExportButtons()}
                  
                  <button 
                    className="btn-action-icon material-btn icon"
                    onClick={togglePreviewVisibility}
                    title="Hide Preview"
                  >
                    <FaEyeSlash />
                  </button>
                </div>
              </div>
              
              <div className="preview-content-full" ref={resumeRef}>
                <div className="resume-template-full material-design-pdf">
                  {/* Header Section */}
                  <div className="resume-header-full">
                    {formData.fullName && (
                      <h1 className="candidate-name-full">{formData.fullName}</h1>
                    )}
                    <div className="contact-info-minimal">
                      <div className="contact-row">
                        {formData.email && <span className="contact-item"><FaEnvelope /> {formData.email}</span>}
                        {formData.phone && (
                          <>
                            <span className="separator">|</span>
                            <span className="contact-item">
                              <FaPhone /> {formData.phone}
                            </span>
                          </>
                        )}
                        {formData.address && (
                          <>
                            <span className="separator">|</span>
                            <span className="contact-item">
                              <FaMapMarkerAlt /> {formData.address}
                            </span>
                          </>
                        )}
                      </div>
                      <div className="social-row">
                        {formData.personalLinks.GitHub && (
                          <a 
                            href={formatSocialLink('github', formData.personalLinks.GitHub)}
                            target="_blank"
                            rel="noopener noreferrer"
                            className="social-item"
                          >
                            <FaGithub /> GitHub
                          </a>
                        )}
                        {formData.personalLinks.LinkedIn && (
                          <>
                            <span className="separator">|</span>
                            <a 
                              href={formatSocialLink('linkedin', formData.personalLinks.LinkedIn)}
                              target="_blank"
                              rel="noopener noreferrer"
                              className="social-item"
                            >
                              <FaLinkedin /> LinkedIn
                            </a>
                          </>
                        )}
                        {formData.personalLinks.Portfolio && (
                          <>
                            <span className="separator">|</span>
                            <a 
                              href={formatSocialLink('portfolio', formData.personalLinks.Portfolio)}
                              target="_blank"
                              rel="noopener noreferrer"
                              className="social-item"
                            >
                              <FaGlobe /> Portfolio
                            </a>
                          </>
                        )}
                      </div>
                    </div>
                  </div>
                  
                  {/* Summary Section */}
                  {formData.summary && (
                    <div className="resume-section-full">
                      <h2 className="section-title-full material-divider">SUMMARY</h2>
                      <div className="section-content">
                        <p className="summary-text-full">{formData.summary}</p>
                      </div>
                    </div>
                  )}
                  
                  {/* Experience Section */}
                  {formData.experience.some(exp => exp.company.trim()) && (
                    <div className="resume-section-full">
                      <h2 className="section-title-full material-divider">EXPERIENCE</h2>
                      <div className="section-content">
                        {formData.experience.filter(exp => exp.company.trim()).map((exp, index) => (
                          <div key={index} className="experience-item-full material-card">
                            <div className="experience-header">
                              <div className="company-info">
                                <h3 className="company-name-full">{exp.company}</h3>
                                {exp.type && (
                                  <span className="job-type-badge material-chip">{exp.type}</span>
                                )}
                              </div>
                              {exp.duration && (
                                <div className="duration">
                                  <FaCalendarAlt /> {exp.duration}
                                </div>
                              )}
                            </div>
                            
                            {exp.position && (
                              <div className="position-full">
                                <strong>{exp.position}</strong>
                              </div>
                            )}
                            
                            {exp.points.filter(point => point.trim()).length > 0 && (
                              <ul className="achievements-list-full">
                                {exp.points.filter(point => point.trim()).map((point, i) => (
                                  <li key={i} className="achievement-item">
                                    <span className="bullet-point">•</span>
                                    <span className="point-text">{point}</span>
                                  </li>
                                ))}
                              </ul>
                            )}
                            
                            {index < formData.experience.filter(exp => exp.company.trim()).length - 1 && (
                              <hr className="experience-separator" />
                            )}
                          </div>
                        ))}
                      </div>
                    </div>
                  )}
                  
                  {/* Education Section */}
                  {formData.education.some(edu => edu.institution.trim()) && (
                    <div className="resume-section-full">
                      <h2 className="section-title-full material-divider">EDUCATION</h2>
                      <div className="section-content">
                        {formData.education.filter(edu => edu.institution.trim()).map((edu, index) => (
                          <div key={index} className="education-item-full material-card">
                            <div className="education-header">
                              <div>
                                <h3 className="institution-full">{edu.institution}</h3>
                                {edu.degree && (
                                  <div className="degree-full">
                                    {edu.degree}
                                    {edu.score && (
                                      <span className="gpa-score"> | CGPA: {edu.score}</span>
                                    )}
                                  </div>
                                )}
                              </div>
                              <div className="education-meta">
                                {edu.year && (
                                  <span className="year-full">
                                    <FaCalendarAlt /> {edu.year}
                                  </span>
                                )}
                                {edu.location && (
                                  <span className="location-full">
                                    <FaMapMarkerAlt /> {edu.location}
                                  </span>
                                )}
                              </div>
                            </div>
                          </div>
                        ))}
                      </div>
                    </div>
                  )}
                  
                  {/* Projects Section */}
                  {formData.projects.some(proj => proj.name.trim()) && (
                    <div className="resume-section-full">
                      <h2 className="section-title-full material-divider">PROJECTS</h2>
                      <div className="section-content">
                        {formData.projects.filter(proj => proj.name.trim()).map((project, index) => (
                          <div key={index} className="project-item-full material-card">
                            <div className="project-header">
                              <h3 className="project-name-full">{project.name}</h3>
                            </div>
                            
                            {project.points.filter(point => point.trim()).length > 0 && (
                              <ul className="project-features-full">
                                {project.points.filter(point => point.trim()).map((point, i) => (
                                  <li key={i} className="feature-item">
                                    <span className="bullet-point">•</span>
                                    <span className="point-text">{point}</span>
                                  </li>
                                ))}
                              </ul>
                            )}
                            
                            {project.technologies && (
                              <div className="technologies-full material-chip-container">
                                <strong>Technologies used:</strong> 
                                <span className="material-chip-list">
                                  {project.technologies.split(',').map((tech, i) => (
                                    <span key={i} className="material-chip">{tech.trim()}</span>
                                  ))}
                                </span>
                              </div>
                            )}
                            
                            {index < formData.projects.filter(proj => proj.name.trim()).length - 1 && (
                              <hr className="project-separator" />
                            )}
                          </div>
                        ))}
                      </div>
                    </div>
                  )}
                  
                  {/* TECHNICAL SKILLS Section */}
                  {Object.values(formData.technicalSkills).some(skill => skill.trim()) && (
                    <div className="resume-section-full">
                      <h2 className="section-title-full material-divider">TECHNICAL SKILLS</h2>
                      <div className="section-content">
                        <div className="skills-list-full material-chip-container">
                          {formData.technicalSkills.languages && (
                            <div className="skill-item-full">
                              <strong>Programming Languages:</strong> 
                              <span className="material-chip-list">
                                {formData.technicalSkills.languages.split(',').map((lang, i) => (
                                  <span key={i} className="material-chip">{lang.trim()}</span>
                                ))}
                              </span>
                            </div>
                          )}
                          {formData.technicalSkills.frontEnd && (
                            <div className="skill-item-full">
                              <strong>Frontend Technologies:</strong> 
                              <span className="material-chip-list">
                                {formData.technicalSkills.frontEnd.split(',').map((tech, i) => (
                                  <span key={i} className="material-chip">{tech.trim()}</span>
                                ))}
                              </span>
                            </div>
                          )}
                          {formData.technicalSkills.backEnd && (
                            <div className="skill-item-full">
                              <strong>Backend Technologies:</strong> 
                              <span className="material-chip-list">
                                {formData.technicalSkills.backEnd.split(',').map((tech, i) => (
                                  <span key={i} className="material-chip">{tech.trim()}</span>
                                ))}
                              </span>
                            </div>
                          )}
                          {formData.technicalSkills.database && (
                            <div className="skill-item-full">
                              <strong>Databases:</strong> 
                              <span className="material-chip-list">
                                {formData.technicalSkills.database.split(',').map((db, i) => (
                                  <span key={i} className="material-chip">{db.trim()}</span>
                                ))}
                              </span>
                            </div>
                          )}
                          {formData.technicalSkills.tools && (
                            <div className="skill-item-full">
                              <strong>Tools & Platforms:</strong> 
                              <span className="material-chip-list">
                                {formData.technicalSkills.tools.split(',').map((tool, i) => (
                                  <span key={i} className="material-chip">{tool.trim()}</span>
                                ))}
                              </span>
                            </div>
                          )}
                        </div>
                      </div>
                    </div>
                  )}
                </div>
              </div>
            </div>
          )}
        </div>
        
        {/* Preview Toggle Button for Mobile */}
        {!isPreviewVisible && (
          <button className="preview-toggle-fab material-btn primary" onClick={togglePreviewVisibility}>
            <FaEye /> Show Preview
          </button>
        )}
      </main>

      {/* Loading Overlay */}
      {(isLoading || isSaving || isCheckingResume || isApiLoading) && (
        <div className="loading-overlay">
          <div className="loading-spinner material-spinner"></div>
          <p>
            {isSaving ? 'Saving to database...' : 
             isLoading ? 'Generating PDF...' : 
             isCheckingResume ? 'Checking for existing resume...' :
             'Processing...'}
          </p>
          <p className="loading-subtext">Please don't close this window</p>
        </div>
      )}
    </div>
  );
};

export default App;