#include "game.h"
#include "socket/socket_tcp.h"

typedef struct game {
	int id;
	struct ev_loop_ctx* loop_ctx;
	struct ev_timer timer;
	struct ev_connecter* netd_connecter;
	
} game_t;

game_t*
game_create(struct ev_loop_ctx* loop_ctx, int id, int game_type) {
	game_t* game = malloc(sizeof(*game));
	memset(game, 0, sizeof(*game));
	game->id = id;
	return game;
}

int main() {
	return 0;
}