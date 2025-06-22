import { Button } from '@repo/shadcn/button';
import { cn } from '@repo/shadcn/lib/utils';
import { useToolbar } from '@repo/shadcn/tiptap/toolbars/toolbar-provider';
import { IconBrandYoutubeFilled } from '@tabler/icons-react';

const YoutubeToolbar = () => {
  const { editor } = useToolbar();

  return (
    <Button
      variant="ghost"
      size="icon"
      className={cn('h-8 w-8 p-0 sm:h-9 sm:w-9')}
      onClick={() => {
        const videoLink = prompt('Please enter Youtube Video Link');
        //From https://regexr.com/3dj5t
        const ytregex = new RegExp(
          /^((?:https?:)?\/\/)?((?:www|m)\.)?((?:youtube\.com|youtu.be))(\/(?:[\w-]+\?v=|embed\/|v\/)?)([\w-]+)(\S+)?$/,
        );

        if (videoLink && ytregex.test(videoLink)) {
          editor.commands.insertContent({
            type: 'youtube',
            attrs: {
              src: videoLink,
              width: '100%',
              align: 'center',
              height: '550',
              caption: 'Youtube Video Link',
            },
          });
        } else {
          if (videoLink !== null) {
            alert('Please enter a correct Youtube Video Link');
          }
        }
      }}
    >
      <IconBrandYoutubeFilled className="size-4" />
    </Button>
  );
};

export default YoutubeToolbar;
