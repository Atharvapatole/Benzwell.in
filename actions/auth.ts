'use server';

import { createClient } from '@/lib/supabase/server';
import { createAdminClient } from '@/lib/supabase/admin';
import { RegisterSchema, LoginSchema, AdminLoginSchema, VerifyOtpSchema, ResendOtpSchema } from '@/schemas';
import { requestVerificationOTP, verifyUserOTP } from '@/services/otp';
import {
  sendWelcomeEmail,
  sendPasswordResetEmail,
  sendPasswordChangedConfirmationEmail,
} from '@/lib/email/resend';
import { getBaseUrl } from '@/lib/utils';
import { redirect } from 'next/navigation';

export async function registerCustomer(prevState: any, formData: FormData) {
  const rawData = {
    fullName: formData.get('fullName'),
    email: formData.get('email'),
    phone: formData.get('phone'),
    password: formData.get('password'),
    confirmPassword: formData.get('confirmPassword'),
  };

  const parsed = RegisterSchema.safeParse(rawData);
  if (!parsed.success) {
    return {
      success: false,
      error: parsed.error.errors[0]?.message || 'Invalid form data',
    };
  }

  const { fullName, email, phone, password } = parsed.data;
  const normalizedEmail = email.toLowerCase().trim();
  const supabase = await createClient();

  // 1. Check if user already exists in profiles
  const adminClient = createAdminClient();
  const { data: existingProfile } = await adminClient
    .from('profiles')
    .select('id, is_verified')
    .eq('email', normalizedEmail)
    .maybeSingle();

  if (existingProfile) {
    return {
      success: false,
      error: 'An account with this email already exists. Please sign in.',
    };
  }

  // 2. Sign up via Supabase Auth
  const baseUrl = getBaseUrl();
  const { data: authData, error: authError } = await supabase.auth.signUp({
    email: normalizedEmail,
    password,
    options: {
      emailRedirectTo: `${baseUrl}/auth/callback`,
      data: {
        full_name: fullName,
        phone: phone || '',
        role: 'customer',
        is_verified: false,
      },
    },
  });

  if (authError || !authData.user) {
    const msg = authError?.message?.toLowerCase() || '';
    if (msg.includes('signups are disabled')) {
      return {
        success: false,
        error: "Email signups are disabled in Supabase. Please enable 'Allow new users to sign up' under Authentication -> Providers -> Email in your Supabase Dashboard.",
      };
    }
    return {
      success: false,
      error: authError?.message || 'Failed to create account. Please try again.',
    };
  }

  // 3. Ensure profile is saved in public.profiles table
  await adminClient
    .from('profiles')
    .upsert({
      id: authData.user.id,
      email: normalizedEmail,
      full_name: fullName,
      phone: phone || null,
      role: 'customer',
      is_verified: false,
    });

  // 4. Send welcome email asynchronously via Resend
  sendWelcomeEmail({ email: normalizedEmail, customerName: fullName }).catch(() => {});

  const requiresVerification = !authData.session || !authData.user?.email_confirmed_at;

  return {
    success: true,
    email: normalizedEmail,
    requiresVerification: true,
    message: 'Account created successfully! Please check your email to activate your account.',
  };
}

export async function resendConfirmationEmailAction(email: string) {
  if (!email || !email.includes('@')) {
    return { success: false, message: 'Please provide a valid email address.' };
  }

  const normalizedEmail = email.toLowerCase().trim();
  const baseUrl = getBaseUrl();
  const supabase = await createClient();

  try {
    const { error } = await supabase.auth.resend({
      type: 'signup',
      email: normalizedEmail,
      options: {
        emailRedirectTo: `${baseUrl}/auth/callback`,
      },
    });

    if (error) {
      console.warn('Supabase auth.resend error:', error.message);
      return {
        success: false,
        message: error.message || 'Failed to resend confirmation email. Please try again later.',
      };
    }

    return {
      success: true,
      message: 'A fresh confirmation link has been sent to your email.',
    };
  } catch (err: any) {
    console.error('resendConfirmationEmailAction error:', err);
    return {
      success: false,
      message: err.message || 'Failed to resend confirmation email.',
    };
  }
}

export async function loginCustomer(prevState: any, formData: FormData) {
  const rawData = {
    email: formData.get('email'),
    password: formData.get('password'),
  };

  const parsed = LoginSchema.safeParse(rawData);
  if (!parsed.success) {
    return {
      success: false,
      error: parsed.error.errors[0]?.message || 'Invalid email or password',
    };
  }

  const { email, password } = parsed.data;
  const supabase = await createClient();

  const { data, error } = await supabase.auth.signInWithPassword({
    email: email.toLowerCase().trim(),
    password,
  });

  if (error || !data.user) {
    const msg = error?.message?.toLowerCase() || '';
    if (msg.includes('email logins are disabled') || msg.includes('signups are disabled')) {
      return {
        success: false,
        error: 'Email provider is disabled in Supabase Dashboard. Please enable Email Provider under Authentication -> Providers -> Email in your Supabase project.',
      };
    }
    if (msg.includes('email not confirmed')) {
      return {
        success: false,
        error: 'Your email address has not been confirmed yet. Please check your inbox or verify your account.',
      };
    }
    return {
      success: false,
      error: error?.message || 'Invalid email or password. Please try again.',
    };
  }

  // Check if profile is disabled
  const adminClient = createAdminClient();
  const { data: profile } = await adminClient
    .from('profiles')
    .select('is_disabled, is_verified, role')
    .eq('id', data.user.id)
    .single();

  if (profile?.is_disabled) {
    await supabase.auth.signOut();
    return {
      success: false,
      error: 'Your account has been suspended. Please contact support at info@benzwell.in.',
    };
  }

  return {
    success: true,
    isVerified: profile?.is_verified ?? true,
    role: profile?.role || 'customer',
  };
}

export async function adminLoginAction(prevState: any, formData: FormData) {
  const rawData = {
    email: formData.get('email'),
    password: formData.get('password'),
  };

  const parsed = AdminLoginSchema.safeParse(rawData);
  if (!parsed.success) {
    return {
      success: false,
      error: parsed.error.errors[0]?.message || 'Invalid email or password format.',
    };
  }

  const { email, password } = parsed.data;
  const normalizedEmail = email.toLowerCase().trim();
  const supabase = await createClient();

  // 1. Supabase Authentication
  const { data, error } = await supabase.auth.signInWithPassword({
    email: normalizedEmail,
    password,
  });

  if (error || !data.user) {
    const msg = error?.message?.toLowerCase() || '';
    if (msg.includes('email logins are disabled') || msg.includes('signups are disabled')) {
      return {
        success: false,
        error: 'Email provider is currently disabled in your Supabase Dashboard. Please enable Email provider under Authentication -> Providers -> Email.',
      };
    }
    if (msg.includes('email not confirmed')) {
      return {
        success: false,
        error: 'Admin email is not confirmed in Supabase Auth.',
      };
    }
    return {
      success: false,
      error: error?.message || 'Incorrect email or password.',
    };
  }

  // 2. Strict Server-Side Role Verification from Database
  const adminClient = createAdminClient();
  const { data: profile, error: profileError } = await adminClient
    .from('profiles')
    .select('id, email, role, is_disabled')
    .eq('id', data.user.id)
    .maybeSingle();

  // Handle missing profile
  if (!profile) {
    await supabase.auth.signOut();
    return {
      success: false,
      error: 'Your account does not have administrator access.',
    };
  }

  // Handle suspended account
  if (profile.is_disabled) {
    await supabase.auth.signOut();
    return {
      success: false,
      error: 'Your administrative account has been suspended. Please contact support.',
    };
  }

  // Handle non-admin role
  if (profile.role !== 'admin' && profile.role !== 'super_admin') {
    await supabase.auth.signOut();
    return {
      success: false,
      error: 'Your account does not have administrator access.',
    };
  }

  // 3. Log successful admin login to audit logs
  try {
    await adminClient.from('audit_logs').insert({
      user_id: data.user.id,
      user_email: normalizedEmail,
      action: 'ADMIN_LOGIN_SUCCESS',
      entity: 'auth',
      entity_id: data.user.id,
      metadata: { timestamp: new Date().toISOString() },
    });
  } catch (auditErr) {
    console.error('Failed to log admin login audit:', auditErr);
  }

  return {
    success: true,
  };
}

/**
 * Send Password Reset Link via Supabase Auth + Resend
 */
export async function sendForgotPasswordResetAction(email: string) {
  if (!email || !email.includes('@')) {
    return { success: false, error: 'Please enter a valid email address.' };
  }

  const normalizedEmail = email.toLowerCase().trim();
  const baseUrl = getBaseUrl();
  const adminClient = createAdminClient();

  try {
    // 1. Generate secure time-limited recovery link via Supabase Auth
    const { data: linkData, error: linkError } = await adminClient.auth.admin.generateLink({
      type: 'recovery',
      email: normalizedEmail,
      options: {
        redirectTo: `${baseUrl}/reset-password`,
      },
    });

    if (linkError) {
      console.warn('Supabase generateLink recovery error:', linkError.message);
      // Return neutral message for security (prevent email harvesting)
      return {
        success: true,
        message: 'If an account exists with this email address, a secure password reset link has been sent.',
      };
    }

    const actionLink = linkData?.properties?.action_link;
    if (actionLink) {
      // 2. Fetch customer name if profile exists
      const { data: profile } = await adminClient
        .from('profiles')
        .select('full_name')
        .eq('email', normalizedEmail)
        .maybeSingle();

      // 3. Deliver email strictly via Resend
      await sendPasswordResetEmail({
        email: normalizedEmail,
        customerName: profile?.full_name || 'Valued Customer',
        resetUrl: actionLink,
      });
    }

    return {
      success: true,
      message: 'If an account exists with this email address, a secure password reset link has been sent to your inbox.',
    };
  } catch (err: any) {
    console.error('sendForgotPasswordResetAction exception:', err);
    return {
      success: true,
      message: 'If an account exists with this email address, a secure password reset link has been sent.',
    };
  }
}

/**
 * Update Customer Password via Authenticated / Recovery Session
 */
export async function updatePasswordAction(newPassword: string) {
  if (!newPassword || newPassword.length < 6) {
    return { success: false, error: 'Password must be at least 6 characters long.' };
  }

  const supabase = await createClient();
  const {
    data: { user },
  } = await supabase.auth.getUser();

  if (!user) {
    return {
      success: false,
      error: 'Your password reset session has expired or is invalid. Please request a new reset link.',
    };
  }

  const { error } = await supabase.auth.updateUser({
    password: newPassword,
  });

  if (error) {
    return { success: false, error: error.message || 'Failed to update password.' };
  }

  // Send confirmation email asynchronously via Resend
  sendPasswordChangedConfirmationEmail({
    email: user.email || '',
    customerName: user.user_metadata?.full_name || 'Customer',
  }).catch(() => {});

  return { success: true };
}

export async function verifyOtpAction(prevState: any, formData: FormData) {
  const rawData = {
    email: formData.get('email'),
    otp: formData.get('otp'),
  };

  const parsed = VerifyOtpSchema.safeParse(rawData);
  if (!parsed.success) {
    return {
      success: false,
      message: parsed.error.errors[0]?.message || 'Invalid 6-digit code',
    };
  }

  const res = await verifyUserOTP({
    email: parsed.data.email,
    otp: parsed.data.otp,
    type: 'email_verification',
  });

  return res;
}

export async function resendOtpAction(prevState: any, formData: FormData) {
  const rawData = {
    email: formData.get('email'),
  };

  const parsed = ResendOtpSchema.safeParse(rawData);
  if (!parsed.success) {
    return {
      success: false,
      message: 'Invalid email address',
    };
  }

  const res = await requestVerificationOTP({
    email: parsed.data.email,
    type: 'email_verification',
  });

  return res;
}

export async function signOutAction() {
  const supabase = await createClient();
  await supabase.auth.signOut();
  redirect('/login');
}

export async function adminSignOutAction() {
  const supabase = await createClient();
  await supabase.auth.signOut();
  redirect('/admin/login');
}
