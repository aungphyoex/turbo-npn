'use client';
import { useSession } from 'next-auth/react';

const Session = () => {
  useSession({
    required: true,
  });
  return <></>;
};

export default Session;
