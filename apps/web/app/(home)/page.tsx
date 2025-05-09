import { ModeSwitcher } from '@repo/shadcn/mode-switcher';
import { VideoPlayer } from '@repo/shadcn/video/player';

const Page = () => {
  return (
    <section className="min-h-dvh container">
      <nav className="flex justify-between items-center py-2">
        <h1 className="font-semibold">Turborepo</h1>
        <ModeSwitcher />
      </nav>
      <div className="flex justify-center items-center">
        <VideoPlayer
          poster={
            'https://images.unsplash.com/photo-1745282480794-10427e218c76'
          }
          src="https://commondatastorage.googleapis.com/gtv-videos-bucket/sample/ElephantsDream.mp4"
          className="w-full lg:w-[600px] h-[400px] lg:h-[600px]"
        />
      </div>
    </section>
  );
};

export default Page;
