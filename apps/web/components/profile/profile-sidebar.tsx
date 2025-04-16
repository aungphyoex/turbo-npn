'use client';

import SignOut from '@/components/auth/sign-out';
import { Button } from '@repo/shadcn/button';
import { cn } from '@repo/shadcn/lib/utils';
import { Shield, Smartphone, User } from '@repo/shadcn/lucide-react';
import Link from 'next/link';
import { usePathname } from 'next/navigation';

const ProfileSidebar = () => {
  const menuItems = [
    { id: 'general', label: 'General', icon: User, href: '/profile' },
    {
      id: 'security',
      label: 'Security and Login',
      icon: Shield,
      href: '/profile/security',
    },
    {
      id: 'sessions',
      label: 'Active Sessions',
      icon: Smartphone,
      href: '/profile/sessions',
    },
  ];
  const pathname = usePathname();
  return (
    <div className="bg-card rounded-lg shadow p-4">
      <h2 className="font-semibold text-lg mb-4">Settings</h2>
      <nav className="space-y-1">
        {menuItems.map((item) => {
          const Icon = item.icon;
          return (
            <Button
              key={item.id}
              variant={pathname === item.href ? 'secondary' : 'ghost'}
              className={cn(
                `w-full justify-start`,
                pathname === item.href && 'bg-secondary',
              )}
              asChild
            >
              <Link href={item.href}>
                <Icon className="mr-2 h-4 w-4" />
                {item.label}
              </Link>
            </Button>
          );
        })}

        <SignOut />
      </nav>
    </div>
  );
};

export default ProfileSidebar;
