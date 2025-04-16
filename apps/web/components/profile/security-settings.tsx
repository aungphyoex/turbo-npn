'use client';

import ChangePasswordForm from '@/components/auth/form/change-password.form';

const SecuritySettings = () => {
  return (
    <div className="space-y-6">
      <ChangePasswordForm />
      {/*<ChangeEmailForm/>*/}
    </div>
  );
};

export default SecuritySettings;
